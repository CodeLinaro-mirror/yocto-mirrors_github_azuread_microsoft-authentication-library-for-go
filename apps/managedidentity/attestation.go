// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrAttestationUnavailable reports that this host cannot produce a KeyGuard
// attestation statement, which is different from producing one and having it
// rejected. Attestation depends on AttestationClientLib.dll, a native component
// that is distributed separately and is not part of this module.
//
// This only ever reaches a caller who asked for attestation with
// WithAttestationSupport(), and it is an error rather than a downgrade: having
// asked, the caller is not quietly handed a credential that lacks it. A caller
// who did not ask never attempts attestation and never sees this.
//
// Match it with errors.Is.
var ErrAttestationUnavailable = errors.New("managedidentity: KeyGuard attestation is not available on this host")

// attestKeyGuardFn is the attestation entry point, indirected through a variable
// so a test can supply a provider on a host without KeyGuard. MSAL .NET exposes
// an equivalent hook on PopKeyAttestor for the same reason.
var attestKeyGuardFn = attestKeyGuard

// attestationExpiryBuffer is how long before its own expiry an attestation token
// stops being served from the cache, so a token is never handed out with so
// little life left that the service rejects it by the time it is read. It
// matches the buffer MSAL .NET applies to the same cache.
const attestationExpiryBuffer = 5 * time.Minute

type attestationCacheEntry struct {
	token   string
	expires time.Time
}

// attestationCache holds MAA statements so that minting a second certificate for
// the same key does not pay for a second native call and MAA round trip. MSAL
// .NET caches these the same way, for the same reason.
//
// This matters because one process can hold several certificates over the same
// binding key: a system-assigned and a user-assigned identity have separate
// certificate cache entries, and re-minting after a rejected certificate issues
// another. Each of those would otherwise re-attest a key that MAA has already
// vouched for.
//
// The mutex guards only the map. Issuance already runs under the certificate
// cache lock, so attestation cannot be entered concurrently in the first place,
// which is a stronger guarantee than the per-key semaphore MSAL .NET needs. The
// lock here keeps that from being an unstated dependency on a caller's locking.
var attestationCache = struct {
	mu      sync.Mutex
	entries map[string]attestationCacheEntry
}{entries: map[string]attestationCacheEntry{}}

// attestationCacheKey identifies a cached statement by the endpoint that issued
// it and the key it vouches for.
//
// The endpoint is part of the key because MAA instances issue their own tokens:
// a statement from one region is not valid at another.
//
// The key is identified by a fingerprint of its public half rather than by the
// name of the container holding it. A container is reused across key
// re-creation, so a name would still match after the key inside it changed, and
// the cache would serve a statement vouching for a key that no longer exists
// while the CSR carried the new one. A fingerprint changes when the key does.
//
// The client ID is deliberately absent. MAA attests the key itself and the
// client ID is forwarded as metadata, so identities sharing a binding key share
// a statement. MSAL .NET documents the same decision for the same reason.
func attestationCacheKey(endpoint string, key bindingKey) (string, error) {
	if key.Signer == nil {
		return "", errors.New("managedidentity: the binding key has no signer")
	}
	der, err := x509.MarshalPKIXPublicKey(key.Signer.Public())
	if err != nil {
		return "", fmt.Errorf("managedidentity: fingerprinting the binding key: %w", err)
	}
	sum := sha256.Sum256(der)
	normalized := strings.ToLower(strings.TrimSuffix(endpoint, "/"))
	return normalized + "|" + hex.EncodeToString(sum[:]), nil
}

// attestKeyGuardCached returns a cached statement for this key when one is still
// fresh, and otherwise attests and caches the result.
func attestKeyGuardCached(endpoint, clientID string, key bindingKey) (string, error) {
	cacheKey, keyErr := attestationCacheKey(endpoint, key)
	// A key that cannot be fingerprinted is still attestable; it just cannot be
	// cached, so the flow continues uncached rather than failing.
	if keyErr == nil {
		attestationCache.mu.Lock()
		entry, ok := attestationCache.entries[cacheKey]
		if ok && entry.expires.After(now().Add(attestationExpiryBuffer)) {
			attestationCache.mu.Unlock()
			return entry.token, nil
		}
		if ok {
			delete(attestationCache.entries, cacheKey)
		}
		attestationCache.mu.Unlock()
	}

	token, err := attestKeyGuardFn(endpoint, clientID, key)
	if err != nil {
		return "", err
	}

	// A statement whose lifetime cannot be read is used but not stored: caching
	// it would mean guessing when to stop trusting it. MSAL .NET arrives at the
	// same behaviour by treating a missing expiry as already expired.
	if expires, ok := attestationTokenExpiry(token); ok && keyErr == nil {
		attestationCache.mu.Lock()
		attestationCache.entries[cacheKey] = attestationCacheEntry{token: token, expires: expires}
		attestationCache.mu.Unlock()
	}
	return token, nil
}

// attestationTokenExpiry reads the exp claim of a JWT. It reports whether one
// was found, so a token without a readable lifetime is distinguishable from one
// that expired at the zero time.
func attestationTokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp *int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == nil {
		return time.Time{}, false
	}
	return time.Unix(*claims.Exp, 0), true
}

// clearAttestationCache drops every cached statement. Tests use it to isolate
// themselves from one another, since the cache is process-wide.
func clearAttestationCache() {
	attestationCache.mu.Lock()
	defer attestationCache.mu.Unlock()
	attestationCache.entries = map[string]attestationCacheEntry{}
}
