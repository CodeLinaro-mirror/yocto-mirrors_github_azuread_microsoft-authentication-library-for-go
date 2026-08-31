// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"
)

// certCacheEntry is a cached binding certificate together with the key that
// proves possession of it.
type certCacheEntry struct {
	cert *bindingCertificate
}

// bindingCertCache caches issued binding certificates for the lifetime of the
// process. IMDS rate limits credential issuance, and a certificate is valid for
// far longer than a single token, so re-issuing per token request would be both
// slow and liable to throttling.
//
// The cache is process-wide because the underlying CNG key container is
// process-wide: two Client values configured for the same identity would
// otherwise race to overwrite each other's key.
type bindingCertCache struct {
	mu      sync.Mutex
	entries map[string]*certCacheEntry
}

var certCache = &bindingCertCache{entries: map[string]*certCacheEntry{}}

// cacheKey identifies a binding certificate by the identity the client was
// configured for and whether it was attested.
//
// The configured identity is used rather than the client ID IMDS reports,
// because this key has to be computable before any network call: it is what
// lets a cached token be found without contacting IMDS at all. The reported
// client ID is still checked against the cached certificate before it is
// reused, so an identity reassignment is caught.
//
// Attested and non-attested certificates are deliberately not interchangeable:
// a resource that requires attestation must not be handed a certificate that
// was issued without it, so the flag is part of the key rather than a field on
// the entry.
func cacheKey(id ID, attested bool) string {
	att := "0"
	if attested {
		att = "1"
	}
	return identityKey(id) + "#att=" + att
}

// identityKey renders the configured managed identity as a stable string. The
// kind is included because the same string can be a client ID for one client
// and an object ID for another, and those are different identities.
func identityKey(id ID) string {
	switch t := id.(type) {
	case UserAssignedClientID:
		return "client:" + string(t)
	case UserAssignedObjectID:
		return "object:" + string(t)
	case UserAssignedResourceID:
		return "resource:" + string(t)
	default:
		return "system"
	}
}

// get returns a cached certificate if one is present and still usable. The
// returned certificate carries a reference the caller must release with Close,
// so that a concurrent evict cannot release the key while it is in use.
func (c *bindingCertCache) get(key string) (*bindingCertificate, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry.cert.retain()
	return entry.cert, true
}

// evict drops a certificate and releases its key handle.
func (c *bindingCertCache) evict(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		_ = entry.cert.Close()
		delete(c.entries, key)
	}
}

// clear drops every cached certificate. It exists so tests do not leak state
// between cases.
func (c *bindingCertCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		_ = entry.cert.Close()
		delete(c.entries, key)
	}
}

// isOrphaned reports whether a cached certificate no longer matches the key
// currently in the CNG container.
//
// A VBS key does not survive events that reset the isolated container, and the
// container can also be recreated out from under the process. When that
// happens the cached certificate still parses and still looks valid, but the
// private key behind it is gone, so the TLS handshake fails in a way that is
// hard to attribute. Comparing the public keys detects it up front.
func isOrphaned(cert *bindingCertificate, provider keyProvider) bool {
	current, err := provider.getOrCreateKey(bindingKeyName)
	if err != nil {
		// The key cannot be reached at all, so the cached certificate is not
		// usable either.
		return true
	}
	defer func() { _ = current.Close() }()
	return certificateMatchesKey(cert.Leaf, current) != nil
}

// bindingCertRefreshWindow is how long before its expiry a cached binding
// certificate stops being reused. Presenting a certificate that expires mid
// request costs a wasted mTLS round trip and surfaces as an opaque rejection
// from Entra, so it is re-minted slightly early instead.
const bindingCertRefreshWindow = 5 * time.Minute

// needsRefresh reports whether a cached certificate is at or past its refresh
// window and should be re-minted rather than reused.
func needsRefresh(cert *bindingCertificate) bool {
	if cert == nil || cert.Leaf == nil || cert.Leaf.NotAfter.IsZero() {
		return false
	}
	return !cert.Leaf.NotAfter.After(now().Add(bindingCertRefreshWindow))
}

// getBindingCertificate returns a binding certificate for the identity IMDS
// reports, issuing a new one only when the cache cannot supply a usable one.
//
// The returned certificate carries a reference the caller must release with
// Close.
func (v imdsV2) getBindingCertificate(ctx context.Context, attested bool) (*bindingCertificate, string, error) {
	if !platformSupportsMtlsPoP() {
		return nil, "", ErrMtlsNotSupportedForPlatform
	}
	correlationID := newCorrelationID()
	key := cacheKey(v.miType, attested)

	// Leg 1 runs on every acquisition, even on a cache hit. It is what names the
	// identity, so it is also what detects that the identity assigned to this
	// VM changed underneath a cached certificate.
	metadata, err := v.getCsrMetadata(ctx, correlationID)
	if err != nil {
		return nil, "", err
	}

	// The lock is held across issuance so that concurrent callers do not each
	// mint a key into the same container and invalidate each other's
	// certificate.
	certCache.mu.Lock()
	defer certCache.mu.Unlock()

	if entry, ok := certCache.entries[key]; ok {
		reusable := entry.cert.ClientID == metadata.ClientID &&
			!needsRefresh(entry.cert) &&
			!isOrphaned(entry.cert, v.keyProvider)
		if reusable {
			entry.cert.retain()
			return entry.cert, key, nil
		}
		_ = entry.cert.Close()
		delete(certCache.entries, key)
	}

	cert, err := v.issueBindingCertificate(ctx, correlationID, metadata, attested)
	if err != nil {
		return nil, "", err
	}
	// The cache takes over the reference newBindingCertificate created; the
	// caller gets one of its own.
	certCache.entries[key] = &certCacheEntry{cert: cert}
	cert.retain()
	return cert, key, nil
}

// issueBindingCertificate mints a key and exchanges a CSR for a certificate.
// The caller holds the cache lock.
func (v imdsV2) issueBindingCertificate(ctx context.Context, correlationID string, metadata csrMetadata, attested bool) (*bindingCertificate, error) {
	key, err := v.keyProvider.getOrCreateKey(bindingKeyName)
	if err != nil {
		return nil, err
	}
	// A software key would produce a token shaped like a bound token while
	// offering none of the guarantees, so this refuses rather than downgrades.
	if err := requireKeyGuard(key); err != nil {
		_ = key.Close()
		return nil, err
	}

	csr, err := createCSR(key.Signer, metadata.ClientID, metadata.TenantID, metadata.CuID)
	if err != nil {
		_ = key.Close()
		return nil, err
	}

	// Attestation is attempted only when the caller opted in with
	// WithAttestationSupport(), which mirrors MSAL .NET: without its optional
	// attestation package the provider is unset and the credential request goes
	// out non-attested.
	//
	// Once the caller has opted in, a failure to attest is fatal rather than a
	// downgrade. Falling back would send a non-attested request on behalf of a
	// caller who explicitly asked for attestation, turning a missing native
	// library or an MAA policy denial into a credential that silently carries
	// fewer guarantees than the one requested.
	var attestationToken string
	if attested {
		endpoint, err := metadata.attestationURL()
		if err != nil {
			_ = key.Close()
			return nil, err
		}
		attestationToken, err = attestKeyGuardCached(endpoint, metadata.ClientID, key)
		if err != nil {
			_ = key.Close()
			return nil, err
		}
	}

	issued, err := v.issueCredential(ctx, correlationID, csr, attestationToken)
	if err != nil {
		_ = key.Close()
		return nil, err
	}

	leaf, der, err := parseIssuedCertificate(issued.Certificate)
	if err != nil {
		_ = key.Close()
		return nil, err
	}
	if err := certificateMatchesKey(leaf, key); err != nil {
		_ = key.Close()
		return nil, err
	}

	return newBindingCertificate(der, leaf, key, issued), nil
}

// parseIssuedCertificate decodes the base64 DER IMDS returned.
func parseIssuedCertificate(encoded string) (*x509.Certificate, []byte, error) {
	der, err := decodeCertificate(encoded)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("managedidentity: parsing the issued certificate: %w", err)
	}
	return leaf, der, nil
}
