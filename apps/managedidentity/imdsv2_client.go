// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/google/uuid"
)

// bindingKeyName is the CNG container the IMDSv2 binding key lives in. It is a
// fixed name so the key survives process restarts: re-minting a key on every
// start would mean a fresh certificate on every start, and IMDS rate limits
// credential issuance.
//
// The name is the one MSAL .NET uses, as WindowsCngKeyOperations.KeyGuardKeyName.
// Sharing the container is what lets the two libraries reuse each other's
// binding key and, with it, the certificates persisted against that key: a
// virtual machine running both ends up with one VBS key and one credential
// rather than two of each, and only one call against a rate-limited service.
//
// Both libraries open an existing key before creating one, so sharing the
// container is a read on the common path; the overwrite flag only applies when
// no key is there to open.
const bindingKeyName = "KeyGuardRSAKey"

// imdsV2 carries everything the IMDSv2 legs need. It is split out from Client so
// the IMDS calls can be exercised against a test server without constructing a
// full managed identity client.
type imdsV2 struct {
	httpClient  ops.HTTPClient
	keyProvider keyProvider
	miType      ID
	// retryEnabled carries the client's WithRetryPolicyDisabled setting to the
	// two IMDS legs, which retry on their own rather than through Client.retry.
	retryEnabled bool
	// baseEndpoint is the IMDS root. It is a field so tests can point the two
	// plain-HTTP legs at a local server.
	baseEndpoint string
	// probe marks this as a capability probe rather than an acquisition, which
	// selects the retry policy for the metadata leg. MSAL .NET draws the same
	// distinction with RequestType.ImdsProbe.
	probe bool
}

// metadataRetriableStatus returns the retry policy for the metadata leg.
func (v imdsV2) metadataRetriableStatus() func(int) bool {
	if v.probe {
		return imdsProbeRetriableStatus
	}
	return imdsRetriableStatus
}

// endpoint builds an IMDS URL with the api version and any user-assigned
// identity selector applied.
func (v imdsV2) endpoint(path string) (string, error) {
	u, err := url.Parse(v.baseEndpoint + path)
	if err != nil {
		return "", fmt.Errorf("managedidentity: building the IMDS URL: %w", err)
	}
	q := u.Query()
	q.Set(imdsV2APIVersionQueryParam, imdsV2APIVersion)
	// IMDSv2 names the resource ID parameter mi_res_id, unlike IMDSv1 which uses
	// msi_res_id.
	switch t := v.miType.(type) {
	case UserAssignedClientID:
		q.Set("client_id", string(t))
	case UserAssignedObjectID:
		q.Set("object_id", string(t))
	case UserAssignedResourceID:
		q.Set("mi_res_id", string(t))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// setIMDSHeaders applies the headers both IMDS legs require.
//
// Metadata guards against a request being driven by an attacker who can only
// control a URL. Live IMDS additionally rejects a request that carries no
// x-ms-client-request-id, so both correlation headers are sent.
func setIMDSHeaders(req *http.Request, correlationID string) {
	req.Header.Set(imdsV2MetadataHeader, "true")
	req.Header.Set(imdsV2CorrelationIDHeader, correlationID)
	req.Header.Set(imdsV2ClientRequestIDHeader, correlationID)
}

// readIMDSResponse reads and closes an IMDS response body, turning a non-200
// into an error that carries the service's own description.
func readIMDSResponse(resp *http.Response) ([]byte, error) {
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("managedidentity: reading the IMDS response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("managedidentity: IMDS returned %d: %s", resp.StatusCode, parseIMDSError(body))
	}
	return body, nil
}

// getCsrMetadata performs the first leg, learning which identity this host
// should request a credential for.
func (v imdsV2) getCsrMetadata(ctx context.Context, correlationID string) (csrMetadata, error) {
	target, err := v.endpoint(imdsV2CsrMetadataPath)
	if err != nil {
		return csrMetadata{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return csrMetadata{}, fmt.Errorf("managedidentity: building the platform metadata request: %w", err)
	}
	setIMDSHeaders(req, correlationID)

	resp, err := sendIMDSRequest(ctx, v.httpClient, req, v.retryEnabled, v.metadataRetriableStatus())
	if err != nil {
		return csrMetadata{}, fmt.Errorf("managedidentity: requesting platform metadata: %w", err)
	}
	// A host that serves IMDSv1 only has no platform metadata endpoint at all,
	// which is a capability answer rather than a transient failure. On the
	// acquisition path the retries above have already run, so a 404 reaching
	// here is the host's settled answer rather than an agent that had not
	// finished starting. A probe does not retry a 404 at all, because it is
	// asking whether the endpoint exists and has just been told that it does
	// not.
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return csrMetadata{}, ErrMtlsPoPNotSupportedInIMDSv1
	}
	// The header check happens before the body is trusted: these legs are plain
	// HTTP, so this is the only evidence the responder is really IMDS.
	if err := validateIMDSServerHeader(resp); err != nil {
		resp.Body.Close()
		return csrMetadata{}, err
	}
	body, err := readIMDSResponse(resp)
	if err != nil {
		return csrMetadata{}, err
	}

	var metadata csrMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return csrMetadata{}, fmt.Errorf("managedidentity: parsing platform metadata: %w", err)
	}
	if err := metadata.validate(); err != nil {
		return csrMetadata{}, err
	}
	return metadata, nil
}

// issueCredential performs the second leg, exchanging a CSR for a certificate
// signed by IMDS.
func (v imdsV2) issueCredential(ctx context.Context, correlationID, csr, attestationToken string) (certificateRequestResponse, error) {
	target, err := v.endpoint(imdsV2IssueCredentialPath)
	if err != nil {
		return certificateRequestResponse{}, err
	}
	payload, err := json.Marshal(certificateRequestBody{CSR: csr, AttestationToken: attestationToken})
	if err != nil {
		return certificateRequestResponse{}, fmt.Errorf("managedidentity: building the credential request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(string(payload)))
	if err != nil {
		return certificateRequestResponse{}, fmt.Errorf("managedidentity: building the credential request: %w", err)
	}
	setIMDSHeaders(req, correlationID)
	// MSAL .NET sends this body as StringContent(..., Encoding.UTF8, "application/json"),
	// which puts the charset on the wire.
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := sendIMDSRequest(ctx, v.httpClient, req, v.retryEnabled, imdsRetriableStatus)
	if err != nil {
		return certificateRequestResponse{}, fmt.Errorf("managedidentity: requesting a credential: %w", err)
	}
	// A 404 is deliberately not mapped to ErrMtlsPoPNotSupportedInIMDSv1 here.
	// Only the metadata leg answers that question; reaching this leg means the
	// host already served /getplatformmetadata, so IMDSv2 exists and a 404 is an
	// ordinary request failure. MSAL .NET reports it generically for the same
	// reason.
	if err := validateIMDSServerHeader(resp); err != nil {
		resp.Body.Close()
		return certificateRequestResponse{}, err
	}
	body, err := readIMDSResponse(resp)
	if err != nil {
		return certificateRequestResponse{}, err
	}
	var issued certificateRequestResponse
	if err := json.Unmarshal(body, &issued); err != nil {
		return certificateRequestResponse{}, fmt.Errorf("managedidentity: parsing the issued credential: %w", err)
	}
	if err := issued.validate(); err != nil {
		return certificateRequestResponse{}, err
	}
	return issued, nil
}

// bindingCertificate is the certificate IMDS issued together with the key that
// proves possession of it and the endpoint that will accept it.
//
// The key handle behind TLS.PrivateKey can outlive the cache entry: a caller
// that received this certificate from an earlier acquisition may still be using
// it when a later acquisition evicts or replaces the entry. Releasing the handle
// is therefore reference counted rather than tied to eviction, so evicting can
// never break a certificate a caller is still holding.
type bindingCertificate struct {
	TLS      tls.Certificate
	Leaf     *x509.Certificate
	ClientID string
	TenantID string
	Endpoint string

	mu     sync.Mutex
	refs   int
	closed bool
	// close releases the operating system handle behind the private key.
	close func() error
}

// retain records an additional holder of the binding key. Every retain must be
// paired with a Close.
func (b *bindingCertificate) retain() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refs++
}

// Close drops one reference to the binding key and releases the underlying
// handle once the last holder is gone.
func (b *bindingCertificate) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	if b.refs > 0 {
		b.refs--
	}
	if b.refs > 0 {
		return nil
	}
	b.closed = true
	if b.close == nil {
		return nil
	}
	return b.close()
}

// newCorrelationID returns the identifier that ties the IMDS legs of a single
// acquisition together in service-side logs.
func newCorrelationID() string { return uuid.New().String() }

// decodeCertificate decodes the base64 DER IMDS returns. The certificate is
// sent bare, without PEM armor.
func decodeCertificate(encoded string) ([]byte, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("managedidentity: IMDS issued a certificate that is not valid base64: %w", err)
	}
	return der, nil
}

// newBindingCertificate assembles the certificate and key into a value that can
// be presented on a TLS handshake.
func newBindingCertificate(der []byte, leaf *x509.Certificate, key bindingKey, issued certificateRequestResponse) *bindingCertificate {
	return &bindingCertificate{
		TLS: tls.Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  key.Signer,
			Leaf:        leaf,
		},
		Leaf:     leaf,
		ClientID: issued.ClientID,
		TenantID: issued.TenantID,
		Endpoint: issued.MtlsAuthenticationEndpoint,
		// The caller of this function owns the first reference; the cache takes
		// it over when the certificate is stored.
		refs:  1,
		close: key.Close,
	}
}

// certificateMatchesKey checks that the issued certificate carries the public
// half of the binding key.
func certificateMatchesKey(leaf *x509.Certificate, key bindingKey) error {
	// The comparison is written against crypto.PublicKey rather than any,
	// because that is the parameter type the standard library key types
	// declare, and Go matches method sets by exact signature.
	type publicKeyEqual interface{ Equal(crypto.PublicKey) bool }
	pub, ok := leaf.PublicKey.(publicKeyEqual)
	if !ok {
		return fmt.Errorf("managedidentity: the issued certificate carries an unsupported %T public key", leaf.PublicKey)
	}
	if !pub.Equal(key.Signer.Public()) {
		return errors.New("managedidentity: the certificate IMDS issued does not match the binding key")
	}
	return nil
}

// tokenEndpoint builds the Entra token URL from the issuance response. The host
// is taken from IMDS rather than derived locally, and is required to be https
// so a compromised or spoofed IMDS response cannot downgrade the token leg to
// plaintext or point it at a non-TLS listener.
func (b *bindingCertificate) tokenEndpoint() (string, error) {
	raw := strings.TrimSuffix(b.Endpoint, "/")
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("managedidentity: IMDS returned an unusable mTLS endpoint %q: %w", b.Endpoint, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("managedidentity: IMDS returned a non-https mTLS endpoint %q", b.Endpoint)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("managedidentity: IMDS returned an mTLS endpoint with no host %q", b.Endpoint)
	}
	// Anything the service put in the path, query or fragment is discarded: only
	// the origin is taken from IMDS, and the rest of the URL is built here.
	return fmt.Sprintf("https://%s/%s%s", u.Host, strings.Trim(b.TenantID, "/"), imdsV2OAuthPath), nil
}

// mtlsClientCache holds one client per binding certificate. A client is reused
// across acquisitions so connections are actually pooled, which is what the rest
// of MSAL does (see ops.SetMtlsClientFactory, which caches per thumbprint).
// Building one per acquisition instead would strand an idle TLS connection for
// the transport's idle timeout on every token request.
var mtlsClientCache = struct {
	mu      sync.Mutex
	clients map[string]*http.Client
}{clients: map[string]*http.Client{}}

// mtlsClientCacheLimit bounds the cache. A process needs one client per live
// identity and attestation mode, so the working set is small; the limit only
// stops a long-running process from accumulating a transport per re-mint.
const mtlsClientCacheLimit = 8

// mtlsHTTPClient returns a client that presents the binding certificate. The
// client is keyed by the certificate itself so that replacing the certificate
// cannot reuse a pooled connection authenticated with the previous one.
func mtlsHTTPClient(cert tls.Certificate) *http.Client {
	if len(cert.Certificate) == 0 {
		return newMtlsHTTPClient(cert)
	}
	sum := sha256.Sum256(cert.Certificate[0])
	key := string(sum[:])

	mtlsClientCache.mu.Lock()
	defer mtlsClientCache.mu.Unlock()
	if client, ok := mtlsClientCache.clients[key]; ok {
		return client
	}
	// Evicting only over the limit, rather than every time the certificate
	// changes, is what lets two identities alternate without rebuilding a
	// transport on every acquisition.
	for old, client := range mtlsClientCache.clients {
		if len(mtlsClientCache.clients) < mtlsClientCacheLimit {
			break
		}
		client.CloseIdleConnections()
		delete(mtlsClientCache.clients, old)
	}
	client := newMtlsHTTPClient(cert)
	mtlsClientCache.clients[key] = client
	return client
}

// clearMtlsClientCache drops every cached client, closing idle connections so
// the transports do not outlive whatever they were talking to. Tests use it to
// isolate themselves from each other: the cache is process-wide and retains up
// to mtlsClientCacheLimit entries, so without this a client built against one
// test's server survives into the next.
func clearMtlsClientCache() {
	mtlsClientCache.mu.Lock()
	defer mtlsClientCache.mu.Unlock()
	for key, client := range mtlsClientCache.clients {
		client.CloseIdleConnections()
		delete(mtlsClientCache.clients, key)
	}
}

func newMtlsHTTPClient(cert tls.Certificate) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

// requestEntraToken performs the third leg: a client credentials request over a
// connection authenticated by the binding certificate. When popRequested is
// true the request asks for a certificate-bound token, otherwise it asks for an
// ordinary bearer token that merely travelled over mTLS.
func requestEntraToken(ctx context.Context, client *http.Client, binding *bindingCertificate, resource string, popRequested, retryEnabled bool) (accesstokens.TokenResponse, error) {
	target, err := binding.tokenEndpoint()
	if err != nil {
		return accesstokens.TokenResponse{}, err
	}

	form := url.Values{}
	form.Set("client_id", binding.ClientID)
	form.Set("grant_type", "client_credentials")
	form.Set("scope", scopeForResource(resource))
	if popRequested {
		form.Set("token_type", authority.AccessTokenTypeMtlsPoP)
	} else {
		// The mTLS-bearer path asks for the type explicitly rather than letting
		// ESTS default it, which is what MSAL .NET does. The value is lowercase
		// because that is the request spelling .NET sends; authority's
		// AccessTokenTypeBearer is the capitalised form that appears in the
		// response and is not interchangeable here.
		form.Set("token_type", "bearer")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return accesstokens.TokenResponse{}, fmt.Errorf("managedidentity: building the token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := sendSTSRequest(ctx, client, req, retryEnabled)
	if err != nil {
		return accesstokens.TokenResponse{}, fmt.Errorf("managedidentity: requesting a token over mTLS: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return accesstokens.TokenResponse{}, fmt.Errorf("managedidentity: reading the token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return accesstokens.TokenResponse{}, newEntraTokenError(resp.StatusCode, body)
	}

	var tr accesstokens.TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return accesstokens.TokenResponse{}, fmt.Errorf("managedidentity: parsing the token response: %w", err)
	}
	// The token endpoint does not echo a scope for a managed identity, so the
	// requested resource is recorded as the granted scope. Without this the
	// token is written to the cache with no scope and can never be read back.
	tr.GrantedScopes.Slice = append(tr.GrantedScopes.Slice, resource)
	return tr, nil
}

// scopeForResource turns a resource into the scope the v2 endpoint expects.
//
// MSAL .NET builds this as resource.TrimEnd('/') + "/.default", so the trailing
// slash has to go or a caller passing "https://vault.azure.net/" would ask for a
// double-slashed scope. The suffix is also trimmed first, which .NET does not
// do, so that a resource already written as a scope is not given a second
// "/.default".
func scopeForResource(resource string) string {
	resource = strings.TrimSuffix(resource, "/.default")
	resource = strings.TrimRight(resource, "/")
	return resource + "/.default"
}
