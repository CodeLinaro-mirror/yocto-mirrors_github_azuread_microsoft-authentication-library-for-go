// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
)

// fakeKeyProvider hands out a software RSA key that reports itself as
// KeyGuard-protected. It exists so the protocol can be exercised on hosts
// without Virtualization-based Security; the real provider is covered
// separately by the KeyGuard tests, which only run where VBS is present.
type fakeKeyProvider struct {
	mu      sync.Mutex
	keys    map[string]*rsa.PrivateKey
	typ     keyType
	err     error
	creates int
}

func newFakeKeyProvider() *fakeKeyProvider {
	return &fakeKeyProvider{keys: map[string]*rsa.PrivateKey{}, typ: keyTypeKeyGuard}
}

func (f *fakeKeyProvider) getOrCreateKey(name string) (bindingKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return bindingKey{}, f.err
	}
	key, ok := f.keys[name]
	if !ok {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return bindingKey{}, err
		}
		f.keys[name] = key
		f.creates++
	}
	return bindingKey{Signer: key, Type: f.typ, Close: func() error { return nil }}, nil
}

func (f *fakeKeyProvider) deleteKey(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.keys, name)
	return nil
}

// rotate replaces the stored key without deleting the name, simulating a VBS
// container that was recreated underneath a cached certificate.
func (f *fakeKeyProvider) rotate(t *testing.T, name string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[name] = key
}

// imdsFake is a stand-in for the metadata service and the Entra token endpoint.
type imdsFake struct {
	t *testing.T

	metadataServer *httptest.Server
	tokenServer    *httptest.Server

	caCert *x509.Certificate
	caKey  *rsa.PrivateKey

	mu sync.Mutex
	// calls records every request path in order, so a test can assert exactly
	// how many round trips an acquisition needed.
	calls []string

	clientID string
	tenantID string

	// omitServerHeader and serverHeader control the anti-spoofing header.
	omitServerHeader bool
	serverHeader     string

	metadataStatus int
	issueStatus    int

	// tokenFailures is the number of leading token requests that fail with
	// tokenFailureBody before one succeeds.
	tokenFailures    int
	tokenFailureCode int
	tokenFailureBody string

	// tokenType is what the token endpoint claims it issued.
	tokenType string
	// lastTokenForm is the form body of the most recent token request.
	lastTokenForm url.Values
	// sawClientCert records whether the token request presented a certificate.
	sawClientCert bool
	// presentedCert is the leaf the client presented on the last token request.
	presentedCert *x509.Certificate
}

func newIMDSFake(t *testing.T) *imdsFake {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "imds-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	f := &imdsFake{
		t:              t,
		caCert:         ca,
		caKey:          caKey,
		clientID:       "8c8a1b0a-4d40-4d9e-9a4f-1f2a3b4c5d6e",
		tenantID:       "72f988bf-86f1-41af-91ab-2d7cd011db47",
		serverHeader:   "IMDS/150.870.65.2153",
		metadataStatus: http.StatusOK,
		issueStatus:    http.StatusOK,
		tokenType:      "mtls_pop",
	}

	f.metadataServer = httptest.NewServer(http.HandlerFunc(f.handleMetadata))
	// The token endpoint requests a client certificate but does not require a
	// verified chain, so a test can inspect what was presented while still
	// letting the handshake complete.
	f.tokenServer = httptest.NewUnstartedServer(http.HandlerFunc(f.handleToken))
	f.tokenServer.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	f.tokenServer.StartTLS()

	t.Cleanup(func() {
		f.metadataServer.Close()
		f.tokenServer.Close()
	})
	return f
}

func (f *imdsFake) record(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, path)
}

func (f *imdsFake) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *imdsFake) resetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func (f *imdsFake) writeServerHeader(w http.ResponseWriter) {
	if !f.omitServerHeader {
		w.Header().Set("Server", f.serverHeader)
	}
}

func (f *imdsFake) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "issuecredential") {
		f.handleIssue(w, r)
		return
	}
	f.record("metadata")
	f.writeServerHeader(w)
	if f.metadataStatus != http.StatusOK {
		w.WriteHeader(f.metadataStatus)
		_, _ = w.Write([]byte(`{"error":"identity_not_found","error_description":"no identity"}`))
		return
	}
	if r.Header.Get("Metadata") != "true" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("cred-api-version") != "2.0" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"cuId":                map[string]string{"vmId": "vm-1", "vmssId": "vmss-1"},
		"clientId":            f.clientID,
		"tenantId":            f.tenantID,
		"attestationEndpoint": "https://attestation.example",
	})
}

func (f *imdsFake) handleIssue(w http.ResponseWriter, r *http.Request) {
	f.record("issue")
	f.writeServerHeader(w)
	if f.issueStatus != http.StatusOK {
		w.WriteHeader(f.issueStatus)
		_, _ = w.Write([]byte(`{"error":"bad_request","error_description":"nope"}`))
		return
	}
	var body certificateRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	der, err := base64.StdEncoding.DecodeString(body.CSR)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// The service would reject a CSR it cannot verify, so the fake does too:
	// this is what makes the test prove the key really signed the request.
	if err := csr.CheckSignature(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, leaf, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"client_id":                    f.clientID,
		"tenant_id":                    f.tenantID,
		"certificate":                  base64.StdEncoding.EncodeToString(certDER),
		"identity_type":                "SAMI",
		"mtls_authentication_endpoint": f.tokenServer.Listener.Addr().String(),
	})
}

func (f *imdsFake) handleToken(w http.ResponseWriter, r *http.Request) {
	f.record("token")
	_ = r.ParseForm()

	f.mu.Lock()
	f.lastTokenForm = r.Form
	f.sawClientCert = r.TLS != nil && len(r.TLS.PeerCertificates) > 0
	if f.sawClientCert {
		f.presentedCert = r.TLS.PeerCertificates[0]
	}
	failuresLeft := f.tokenFailures
	if failuresLeft > 0 {
		f.tokenFailures--
	}
	f.mu.Unlock()

	if failuresLeft > 0 {
		code := f.tokenFailureCode
		if code == 0 {
			code = http.StatusUnauthorized
		}
		w.WriteHeader(code)
		body := f.tokenFailureBody
		if body == "" {
			body = `{"error":"invalid_client","error_description":"certificate rejected"}`
		}
		_, _ = w.Write([]byte(body))
		return
	}

	tokenType := f.tokenType
	if r.Form.Get("token_type") == "" {
		tokenType = "Bearer"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "test-access-token",
		"token_type":   tokenType,
		"expires_in":   3599,
		"client_id":    f.clientID,
	})
}

// newTestClient builds a managed identity client wired to the fake.
func (f *imdsFake) newTestClient(t *testing.T, id ID, provider keyProvider) Client {
	t.Helper()
	t.Setenv(identityEndpointEnvVar, "")
	t.Setenv(msiEndpointEnvVar, "")
	t.Setenv(identityHeaderEnvVar, "")
	t.Setenv(imdsEndVar, "")
	t.Setenv(msiSecretEnvVar, "")
	t.Setenv(identityServerThumbprintEnvVar, "")
	t.Setenv(azurePodIdentityAuthorityHostEnvVar, f.metadataServer.URL)

	client, err := New(id, WithHTTPClient(f.metadataServer.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	client.keyProvider = provider
	// The fake's TLS certificate is self-signed, so the token leg needs a
	// transport that trusts it. Everything else about the client is unchanged.
	client.mtlsClientFactory = func(cert tls.Certificate) *http.Client {
		pool := x509.NewCertPool()
		pool.AddCert(f.tokenServer.Certificate())
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					RootCAs:      pool,
					MinVersion:   tls.VersionTLS12,
				},
			},
		}
	}
	return client
}

// withCleanCaches isolates a test from certificates and tokens another test
// cached, since both caches are process-wide.
func withCleanCaches(t *testing.T) {
	t.Helper()
	certCache.clear()
	cacheManager = storage.New(nil)
	platformSupportsMtlsPoP = func() bool { return true }
	t.Cleanup(func() {
		certCache.clear()
		cacheManager = storage.New(nil)
		platformSupportsMtlsPoP = func() bool { return runtime.GOOS == "windows" }
	})
}

func TestIMDSv2AcquiresBoundTokenInThreeCalls(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)

	res, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if res.AccessToken != "test-access-token" {
		t.Fatalf("access token = %q", res.AccessToken)
	}
	if got := fake.calls; len(got) != 3 || got[0] != "metadata" || got[1] != "issue" || got[2] != "token" {
		t.Fatalf("call sequence = %v, want [metadata issue token]", got)
	}
	if !fake.sawClientCert {
		t.Fatal("the token request did not present a client certificate")
	}
	if res.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("token type = %q, want mtls_pop", res.Metadata.TokenType)
	}
	if res.BindingCertificate == nil {
		t.Fatal("BindingCertificate is nil, so the caller cannot call the resource")
	}
	// The certificate handed to the caller must be the one the service saw,
	// otherwise the bound token would be rejected at the resource.
	if !fake.presentedCert.Equal(res.BindingCertificate.Leaf) {
		t.Fatal("BindingCertificate is not the certificate presented on the handshake")
	}
	if got := fake.lastTokenForm.Get("token_type"); got != "mtls_pop" {
		t.Fatalf("token_type form value = %q, want mtls_pop", got)
	}
	if got := fake.lastTokenForm.Get("scope"); got != "https://vault.azure.net/.default" {
		t.Fatalf("scope = %q", got)
	}
	if got := fake.lastTokenForm.Get("grant_type"); got != "client_credentials" {
		t.Fatalf("grant_type = %q", got)
	}
}

func TestIMDSv2ReusesCachedCertificate(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	// A different resource forces a token cache miss while leaving the
	// certificate cache populated.
	fake.resetCalls()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if got := fake.calls; len(got) != 2 || got[0] != "metadata" || got[1] != "token" {
		t.Fatalf("call sequence = %v, want [metadata token]: the certificate should have been reused", got)
	}
	if provider.creates != 1 {
		t.Fatalf("created %d keys, want 1", provider.creates)
	}
}

func TestIMDSv2ServesTokenFromCacheWithoutNetwork(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	fake.resetCalls()
	res, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if fake.callCount() != 0 {
		t.Fatalf("expected no network calls on a cache hit, got %v", fake.calls)
	}
	if res.Metadata.TokenSource != 2 && res.AccessToken != "test-access-token" {
		t.Fatalf("unexpected cached result %+v", res)
	}
}

func TestIMDSv2BoundAndBearerTokensDoNotShareCache(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	bound, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("bound AcquireToken: %v", err)
	}
	if bound.Metadata.TokenType != "mtls_pop" {
		t.Fatalf("bound token type = %q", bound.Metadata.TokenType)
	}

	// The bearer request must not be satisfied by the bound token already in
	// the cache: it is only valid on a connection using the binding
	// certificate, so returning it here would produce a token the caller
	// cannot use.
	fake.resetCalls()
	bearer, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithRequestOverMtls())
	if err != nil {
		t.Fatalf("bearer AcquireToken: %v", err)
	}
	if bearer.Metadata.TokenType == "mtls_pop" {
		t.Fatal("a bearer request was served the certificate-bound token")
	}
	if fake.callCount() == 0 {
		t.Fatal("the bearer request was served from the bound token's cache entry")
	}
	if got := fake.lastTokenForm.Get("token_type"); got != "" {
		t.Fatalf("a bearer request sent token_type=%q", got)
	}
	if !fake.sawClientCert {
		t.Fatal("WithRequestOverMtls did not use a client certificate")
	}
}

func TestIMDSv2RejectsMissingServerHeader(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.omitServerHeader = true
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("expected an error when the responder did not identify itself as IMDS")
	}
	if fake.callCount() != 1 {
		t.Fatalf("the flow continued past the header check: %v", fake.calls)
	}
}

func TestIMDSv2RejectsForeignServerHeader(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.serverHeader = "nginx/1.25.0"
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err == nil {
		t.Fatal("expected an error when another server answered the metadata address")
	}
}

func TestIMDSv2ReportsV1OnlyHost(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.metadataStatus = http.StatusNotFound
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if !errors.Is(err, ErrMtlsPoPNotSupportedInIMDSv1) {
		t.Fatalf("error = %v, want ErrMtlsPoPNotSupportedInIMDSv1", err)
	}
}

func TestIMDSv2RemintsCertificateOnInvalidClient(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)

	// The first token request fails the way Entra reports a certificate it will
	// no longer accept.
	fake.tokenFailures = 1
	res, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if res.AccessToken != "test-access-token" {
		t.Fatalf("access token = %q", res.AccessToken)
	}
	// metadata, issue, token(fail), metadata, issue, token(ok)
	if got := strings.Join(fake.calls, ","); got != "metadata,issue,token,metadata,issue,token" {
		t.Fatalf("call sequence = %v, want a single re-mint and retry", fake.calls)
	}
}

func TestIMDSv2RetriesOnlyOnce(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	fake.tokenFailures = 5
	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("expected the second failure to surface rather than retry forever")
	}
	tokenCalls := 0
	for _, c := range fake.calls {
		if c == "token" {
			tokenCalls++
		}
	}
	if tokenCalls != 2 {
		t.Fatalf("made %d token requests, want exactly 2", tokenCalls)
	}
}

func TestIMDSv2DoesNotRetryOnUnrelatedFailure(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	// invalid_scope is a request problem. Minting a new certificate cannot fix
	// it, so retrying would only double the load on a rate-limited service.
	fake.tokenFailures = 1
	fake.tokenFailureCode = http.StatusBadRequest
	fake.tokenFailureBody = `{"error":"invalid_scope","error_description":"bad scope"}`

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err == nil {
		t.Fatal("expected the error to surface")
	}
	tokenCalls := 0
	for _, c := range fake.calls {
		if c == "token" {
			tokenCalls++
		}
	}
	if tokenCalls != 1 {
		t.Fatalf("made %d token requests, want 1: an unrelated failure must not re-mint", tokenCalls)
	}
}

func TestIMDSv2RejectsBearerTokenForBoundRequest(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	// The service answers a bound-token request with a bearer token, which is
	// what happens when the tenant has not enabled bound tokens.
	fake.tokenType = "Bearer"
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if err == nil {
		t.Fatal("a bearer token was accepted for a request that asked for a bound token")
	}
	if !strings.Contains(err.Error(), "bound") {
		t.Fatalf("error = %v, want it to explain the token was not bound", err)
	}
}

func TestIMDSv2DetectsOrphanedCertificate(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	// Simulate the isolated container being recreated: the cached certificate
	// still parses, but its private key no longer exists.
	provider.rotate(t, bindingKeyName)

	fake.resetCalls()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,issue,token" {
		t.Fatalf("call sequence = %v, want the orphaned certificate to be reissued", fake.calls)
	}
}

func TestIMDSv2RejectsIdentityReassignment(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	// The VM's identity changed. The cached certificate names the old identity
	// and must not be reused.
	fake.clientID = "11111111-2222-3333-4444-555555555555"

	fake.resetCalls()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,issue,token" {
		t.Fatalf("call sequence = %v, want a new certificate after the identity changed", fake.calls)
	}
}

func TestIMDSv2OptionsAreMutuallyExclusive(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithRequestOverMtls())
	if !errors.Is(err, ErrMtlsPoPAndBearerExclusive) {
		t.Fatalf("error = %v, want ErrMtlsPoPAndBearerExclusive", err)
	}
	if fake.callCount() != 0 {
		t.Fatal("an invalid option combination reached the network")
	}
}

func TestIMDSv2RequiresKeyGuard(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	// A software key must not be accepted: it would produce a token that looks
	// bound but offers none of the guarantees.
	provider.typ = keyTypeSoftware
	client := fake.newTestClient(t, SystemAssigned(), provider)

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if !errors.Is(err, ErrCredentialGuardNotAvailable) {
		t.Fatalf("error = %v, want ErrCredentialGuardNotAvailable", err)
	}
}

func TestIMDSv2RejectsUnsupportedPlatform(t *testing.T) {
	withCleanCaches(t)
	platformSupportsMtlsPoP = func() bool { return false }
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if !errors.Is(err, ErrMtlsNotSupportedForPlatform) {
		t.Fatalf("error = %v, want ErrMtlsNotSupportedForPlatform", err)
	}
	if fake.callCount() != 0 {
		t.Fatal("an unsupported platform still contacted the metadata service")
	}
}

func TestIMDSv2PlainAcquisitionIsUnaffected(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	// Without either option the client must keep using IMDSv1 and must not
	// touch the certificate endpoints.
	_, _ = client.AcquireToken(context.Background(), "https://vault.azure.net")
	for _, c := range fake.calls {
		if c == "issue" {
			t.Fatal("a plain acquisition requested a binding certificate")
		}
	}
}

func TestIMDSv2SendsRequiredHeaders(t *testing.T) {
	withCleanCaches(t)
	var metadataHeader, correlation, clientRequest string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadataHeader = r.Header.Get("Metadata")
		correlation = r.Header.Get("X-Ms-Correlation-Id")
		clientRequest = r.Header.Get("x-ms-client-request-id")
		w.Header().Set("Server", "IMDS/1.0")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	v := imdsV2{httpClient: srv.Client(), keyProvider: newFakeKeyProvider(), miType: SystemAssigned(), baseEndpoint: srv.URL}
	_, _ = v.getCsrMetadata(context.Background(), "corr-1")

	if metadataHeader != "true" {
		t.Errorf("Metadata header = %q, want true", metadataHeader)
	}
	if correlation != "corr-1" {
		t.Errorf("X-Ms-Correlation-Id = %q", correlation)
	}
	// Live IMDS rejects a request without this header, so it must be sent even
	// though it duplicates the correlation identifier.
	if clientRequest != "corr-1" {
		t.Errorf("x-ms-client-request-id = %q, want it to be sent", clientRequest)
	}
}

func TestIMDSv2UserAssignedIdentitySelectors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		id    ID
		param string
		value string
	}{
		{"client", UserAssignedClientID("cid"), "client_id", "cid"},
		{"object", UserAssignedObjectID("oid"), "object_id", "oid"},
		{"resource", UserAssignedResourceID("/subscriptions/x"), "mi_res_id", "/subscriptions/x"},
		{"system", SystemAssigned(), "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := imdsV2{miType: tc.id, baseEndpoint: "http://169.254.169.254"}
			got, err := v.endpoint(imdsV2CsrMetadataPath)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(got)
			if err != nil {
				t.Fatal(err)
			}
			u := parsed.Query()
			if u.Get("cred-api-version") != "2.0" {
				t.Errorf("cred-api-version = %q", u.Get("cred-api-version"))
			}
			if tc.param == "" {
				for _, k := range []string{"client_id", "object_id", "mi_res_id"} {
					if u.Get(k) != "" {
						t.Errorf("system assigned identity sent %s=%q", k, u.Get(k))
					}
				}
				return
			}
			if u.Get(tc.param) != tc.value {
				t.Errorf("%s = %q, want %q", tc.param, u.Get(tc.param), tc.value)
			}
		})
	}
}

func TestIMDSv2RejectsNonHTTPSTokenEndpoint(t *testing.T) {
	for _, endpoint := range []string{"http://evil.example", "ftp://evil.example", "://"} {
		b := &bindingCertificate{Endpoint: endpoint, TenantID: "t"}
		if _, err := b.tokenEndpoint(); err == nil {
			t.Errorf("endpoint %q was accepted", endpoint)
		}
	}
	// A bare host is the shape IMDS actually returns and must be accepted.
	b := &bindingCertificate{Endpoint: "mtlsauth.microsoft.com", TenantID: "tid"}
	got, err := b.tokenEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://mtlsauth.microsoft.com/tid/oauth2/v2.0/token" {
		t.Fatalf("token endpoint = %q", got)
	}
}

// signerFor lets the CSR tests reuse a software key through the same interface
// the flow uses.
var _ crypto.Signer = (*rsa.PrivateKey)(nil)
