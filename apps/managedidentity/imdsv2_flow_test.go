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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
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

	// issueFailures is the number of leading credential requests that fail with
	// a retriable status before one succeeds.
	issueFailures int

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
	// lastAttestationToken is the attestation token carried by the most recent
	// issue request, so a test can tell an attested request from a plain one.
	lastAttestationToken string
	// certLifetime is how long an issued binding certificate is valid for. It is
	// settable so a test can drive the refresh window.
	certLifetime time.Duration
	// attestationEndpoint is what leg 1 advertises. It is settable so a test can
	// prove a hostile value is rejected.
	attestationEndpoint string
	// metadataBody, when set, replaces the leg 1 response body verbatim.
	metadataBody string
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
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
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

		// Comfortably outside bindingCertRefreshWindow, so the default fixture
		// certificate is cacheable and reusable. A test that wants to drive the
		// refresh window sets this shorter.
		certLifetime:        30 * 24 * time.Hour,
		attestationEndpoint: "https://attestation.example",
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
	// An IMDSv1 token request carries a resource but no cred-api-version.
	if r.URL.Query().Get("cred-api-version") == "" && r.URL.Query().Get("resource") != "" {
		f.record("v1token")
		f.writeServerHeader(w)
		w.WriteHeader(http.StatusBadRequest)
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
	if f.metadataBody != "" {
		_, _ = w.Write([]byte(f.metadataBody))
		return
	}
	// Real IMDS omits vmssId entirely on a standalone VM rather than sending it
	// empty. The fixture matches a captured response: inventing a shape the
	// service never sends is what let a bad CUID attribute reach production.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"cuId":                map[string]string{"vmId": "vm-1"},
		"clientId":            f.clientID,
		"tenantId":            f.tenantID,
		"attestationEndpoint": f.attestationEndpoint,
	})
}

func (f *imdsFake) handleIssue(w http.ResponseWriter, r *http.Request) {
	f.record("issue")
	f.writeServerHeader(w)
	if f.issueFailures > 0 {
		f.issueFailures--
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
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
	f.lastAttestationToken = body.AttestationToken
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
		NotAfter:     time.Now().Add(f.certLifetime),
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
func (f *imdsFake) newTestClient(t *testing.T, id ID, provider keyProvider, opts ...ClientOption) Client {
	t.Helper()
	t.Setenv(identityEndpointEnvVar, "")
	t.Setenv(msiEndpointEnvVar, "")
	t.Setenv(identityHeaderEnvVar, "")
	t.Setenv(imdsEndVar, "")
	t.Setenv(msiSecretEnvVar, "")
	t.Setenv(identityServerThumbprintEnvVar, "")
	t.Setenv(azurePodIdentityAuthorityHostEnvVar, f.metadataServer.URL)

	client, err := New(id, append([]ClientOption{WithHTTPClient(f.metadataServer.Client())}, opts...)...)
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
	clearAttestationCache()
	clearMtlsClientCache()
	cacheManager = storage.New(nil)
	platformSupportsMtlsPoP = func() bool { return true }
	// The retry schedule is real time. Tests that exercise a retriable status
	// would otherwise wait out the backoff, so the wait is recorded rather than
	// served. A test that cares about the schedule installs its own.
	realWait := retryWait
	retryWait = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	t.Cleanup(func() {
		certCache.clear()
		clearAttestationCache()
		clearMtlsClientCache()
		cacheManager = storage.New(nil)
		platformSupportsMtlsPoP = func() bool { return runtime.GOOS == "windows" }
		retryWait = realWait
	})
}

// withStubAttestation substitutes the attestation provider so a test can drive
// the attested path on a host that has neither KeyGuard nor the native library.
// It returns a pointer to the call count so a test can assert that attestation
// was, or was not, attempted at all.
func withStubAttestation(t *testing.T, token string, err error) *int {
	t.Helper()
	calls := 0
	original := attestKeyGuardFn
	attestKeyGuardFn = func(endpoint, clientID string, key bindingKey) (string, error) {
		calls++
		return token, err
	}
	t.Cleanup(func() { attestKeyGuardFn = original })
	return &calls
}

func TestIMDSv2SendsNoAttestationTokenWithoutOptIn(t *testing.T) {
	withCleanCaches(t)
	calls := withStubAttestation(t, "stub-attestation-jwt", nil)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if *calls != 0 {
		t.Fatalf("attestation was attempted %d times without WithAttestationSupport", *calls)
	}
	if fake.lastAttestationToken != "" {
		t.Fatalf("attestation token = %q, want empty", fake.lastAttestationToken)
	}
}

func TestIMDSv2SendsAttestationTokenWhenOptedIn(t *testing.T) {
	withCleanCaches(t)
	calls := withStubAttestation(t, "stub-attestation-jwt", nil)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("attestation attempted %d times, want 1", *calls)
	}
	if fake.lastAttestationToken != "stub-attestation-jwt" {
		t.Fatalf("attestation token = %q, want stub-attestation-jwt", fake.lastAttestationToken)
	}
}

// A caller that asked for attestation is never quietly downgraded: failing to
// attest has to surface rather than produce a credential without the guarantee
// the caller requested.
func TestIMDSv2FailsWhenAttestationUnavailable(t *testing.T) {
	withCleanCaches(t)
	withStubAttestation(t, "", ErrAttestationUnavailable)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession(), WithAttestationSupport())
	if err == nil {
		t.Fatal("AcquireToken succeeded, so the caller was silently given a non-attested credential")
	}
	if !errors.Is(err, ErrAttestationUnavailable) {
		t.Fatalf("error = %v, want it to wrap ErrAttestationUnavailable", err)
	}
	for _, call := range fake.calls {
		if call == "issue" {
			t.Fatal("a credential request was sent even though attestation failed")
		}
	}
}

// An attested certificate and a plain one are different credentials, so they
// must not share a cache entry in either direction. MSAL .NET separates them
// with an #att tag on the certificate cache key for the same reason.
func TestIMDSv2AttestedAndNonAttestedCertificatesDoNotShareCache(t *testing.T) {
	bound := []AcquireTokenOption{WithMtlsProofOfPossession()}
	attested := []AcquireTokenOption{WithMtlsProofOfPossession(), WithAttestationSupport()}
	for _, tc := range []struct {
		name       string
		first      []AcquireTokenOption
		second     []AcquireTokenOption
		wantSecond string
	}{
		{name: "attested cannot be reused by a plain request", first: attested, second: bound, wantSecond: ""},
		{name: "plain cannot be reused by an attested request", first: bound, second: attested, wantSecond: "stub-attestation-jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withCleanCaches(t)
			withStubAttestation(t, "stub-attestation-jwt", nil)
			fake := newIMDSFake(t)
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", tc.first...); err != nil {
				t.Fatalf("first AcquireToken: %v", err)
			}
			// A different resource misses the token cache, so the certificate
			// cache alone decides whether a new certificate is issued.
			fake.resetCalls()
			if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", tc.second...); err != nil {
				t.Fatalf("second AcquireToken: %v", err)
			}
			issued := false
			for _, call := range fake.calls {
				if call == "issue" {
					issued = true
				}
			}
			if !issued {
				t.Fatal("the second request reused the first certificate, so attested and non-attested credentials shared a cache entry")
			}
			if fake.lastAttestationToken != tc.wantSecond {
				t.Fatalf("attestation token on the second request = %q, want %q", fake.lastAttestationToken, tc.wantSecond)
			}
		})
	}
}

// stubAttestationJWT builds a token shaped like an MAA statement, carrying the
// expiry the cache reads. The signature is not verified anywhere in this flow,
// so an unsigned third segment is enough.
func stubAttestationJWT(t *testing.T, exp time.Time) string {
	t.Helper()
	enc := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := enc(map[string]string{"alg": "none", "typ": "JWT"})
	payload := enc(map[string]any{"exp": exp.Unix(), "iss": "https://maa.test"})
	return header + "." + payload + ".stub-signature"
}

// withCountedAttestation substitutes the attestation provider with one that
// returns whatever tokenFor produces and counts how often it is reached, which
// is what makes a cache hit observable.
func withCountedAttestation(t *testing.T, tokenFor func() string) *int {
	t.Helper()
	calls := 0
	original := attestKeyGuardFn
	attestKeyGuardFn = func(endpoint, clientID string, key bindingKey) (string, error) {
		calls++
		return tokenFor(), nil
	}
	t.Cleanup(func() { attestKeyGuardFn = original })
	return &calls
}

// Two identities on the same host share one binding key, so MAA has already
// vouched for the key by the time the second certificate is minted.
func TestIMDSv2ReusesAttestationTokenForTheSameKey(t *testing.T) {
	withCleanCaches(t)
	token := stubAttestationJWT(t, time.Now().Add(time.Hour))
	calls := withCountedAttestation(t, func() string { return token })
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	system := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := system.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("system-assigned AcquireToken: %v", err)
	}
	user := fake.newTestClient(t, UserAssignedClientID("11111111-2222-3333-4444-555555555555"), provider)
	if _, err := user.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("user-assigned AcquireToken: %v", err)
	}

	if provider.creates != 1 {
		t.Fatalf("created %d keys, want 1: the test needs both identities to share a binding key", provider.creates)
	}
	if *calls != 1 {
		t.Fatalf("attested %d times, want 1: the second certificate should have reused the cached statement", *calls)
	}
	if fake.lastAttestationToken != token {
		t.Fatalf("the second request sent %q, want the cached statement", fake.lastAttestationToken)
	}
}

// A statement close enough to its expiry could lapse before the service reads
// it, so the cache stops serving it before it actually expires.
func TestIMDSv2ReattestsWhenTheAttestationTokenNearsExpiry(t *testing.T) {
	withCleanCaches(t)
	realNow := now
	base := realNow()
	current := base
	now = func() time.Time { return current }
	t.Cleanup(func() { now = realNow })

	calls := withCountedAttestation(t, func() string { return stubAttestationJWT(t, base.Add(10*time.Minute)) })
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("attested %d times on the first acquisition, want 1", *calls)
	}

	// Six minutes on, the statement has four minutes left, which is inside the
	// five-minute buffer.
	current = base.Add(6 * time.Minute)
	certCache.clear()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if *calls != 2 {
		t.Fatalf("attested %d times, want 2: a statement inside the expiry buffer should not be served", *calls)
	}
}

// A statement vouches for one key. If the key behind a container is replaced,
// the cached statement describes a key that is no longer in use and must not be
// sent with a request carrying the new one.
func TestIMDSv2ReattestsWhenTheBindingKeyChanges(t *testing.T) {
	withCleanCaches(t)
	calls := withCountedAttestation(t, func() string { return stubAttestationJWT(t, time.Now().Add(time.Hour)) })
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}

	// The container keeps its name while the key inside it changes, which is
	// what a name-based cache key would fail to notice.
	provider.rotate(t, bindingKeyName)
	certCache.clear()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if *calls != 2 {
		t.Fatalf("attested %d times, want 2: the statement for the replaced key should not have been reused", *calls)
	}
}

// A statement with no readable lifetime is still usable, but there is no basis
// for deciding when to stop trusting it, so it is not stored.
func TestIMDSv2DoesNotCacheAttestationTokenWithoutExpiry(t *testing.T) {
	withCleanCaches(t)
	calls := withCountedAttestation(t, func() string { return "not-a-jwt" })
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	if fake.lastAttestationToken != "not-a-jwt" {
		t.Fatalf("attestation token = %q, want it sent even though it is not cacheable", fake.lastAttestationToken)
	}
	certCache.clear()
	if _, err := client.AcquireToken(context.Background(), "https://storage.azure.com", WithMtlsProofOfPossession(), WithAttestationSupport()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if *calls != 2 {
		t.Fatalf("attested %d times, want 2: a token with no readable expiry should not be cached", *calls)
	}
}

// The endpoint belongs in the cache key because MAA instances issue their own
// statements: one region's token is not valid at another. Trailing slashes and
// casing are incidental to that identity, so they are normalized away.
func TestAttestationCacheKeySeparatesEndpoints(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	bound := bindingKey{Signer: key, Type: keyTypeKeyGuard}

	keyFor := func(endpoint string, bk bindingKey) string {
		t.Helper()
		got, err := attestationCacheKey(endpoint, bk)
		if err != nil {
			t.Fatalf("attestationCacheKey(%q): %v", endpoint, err)
		}
		return got
	}

	eastus := keyFor("https://eastus.attest.azure.net", bound)
	if got := keyFor("https://EastUS.attest.azure.net/", bound); got != eastus {
		t.Errorf("trailing slash and casing changed the key:\n got %q\nwant %q", got, eastus)
	}
	if got := keyFor("https://westus.attest.azure.net", bound); got == eastus {
		t.Error("two regions produced the same key, so a statement could be reused at an endpoint that did not issue it")
	}
	if got := keyFor("https://eastus.attest.azure.net", bindingKey{Signer: other, Type: keyTypeKeyGuard}); got == eastus {
		t.Error("two keys produced the same cache key, so a statement could vouch for the wrong key")
	}
	if _, err := attestationCacheKey("https://eastus.attest.azure.net", bindingKey{}); err == nil {
		t.Error("a binding key with no signer should not produce a cache key")
	}
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
	if res.Metadata.TokenSource != base.TokenSourceCache {
		t.Fatalf("token source = %v, want the cache", res.Metadata.TokenSource)
	}
	if res.AccessToken != "test-access-token" {
		t.Fatalf("access token = %q", res.AccessToken)
	}
	// A cached bound token is only usable alongside the certificate it is bound
	// to, so serving one without the certificate produces a token every
	// resource rejects. This is invisible to an acquisition-only assertion,
	// which is why it is checked on the cache-hit path specifically.
	if res.BindingCertificate == nil {
		t.Fatal("the cached bound token carries no binding certificate, so the caller cannot call the resource")
	}
	if !fake.presentedCert.Equal(res.BindingCertificate.Leaf) {
		t.Fatal("the cached token's binding certificate is not the one the token is bound to")
	}
	if res.BindingCertificateThumbprint() == "" {
		t.Fatal("the cached token's binding certificate has no thumbprint")
	}
	if len(res.BindingCertificate.Certificate) == 0 || res.BindingCertificate.PrivateKey == nil {
		t.Fatal("the cached token's binding certificate cannot be used for a handshake")
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

// A 404 is the answer that decides IMDSv2 is unavailable on this host, so it is
// only believed once the retries are exhausted. An agent that is still starting
// can answer 404 briefly, and treating that as a permanent capability answer
// would fall back to IMDSv1 for the life of the process.
func TestIMDSv2RetriesA404BeforeReportingAV1OnlyHost(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.metadataStatus = http.StatusNotFound
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if !errors.Is(err, ErrMtlsPoPNotSupportedInIMDSv1) {
		t.Fatalf("error = %v, want ErrMtlsPoPNotSupportedInIMDSv1", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,metadata,metadata,metadata" {
		t.Errorf("calls = %q, want the 404 retried three times before it is believed", got)
	}
}

// The retry policy is wired to the client option rather than always on.
func TestIMDSv2HonorsWithRetryPolicyDisabled(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.metadataStatus = http.StatusNotFound
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider(), WithRetryPolicyDisabled())

	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
	if !errors.Is(err, ErrMtlsPoPNotSupportedInIMDSv1) {
		t.Fatalf("error = %v, want ErrMtlsPoPNotSupportedInIMDSv1", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata" {
		t.Errorf("calls = %q, want a single attempt when the retry policy is disabled", got)
	}
}

// A transient failure on the credential leg is retried, and the retried POST
// still carries a usable CSR: the fake would fail to parse an empty body.
func TestIMDSv2RetriesTheCredentialLeg(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.issueFailures = 2
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,issue,issue,issue,token" {
		t.Errorf("calls = %q, want the credential request retried twice and then succeed", got)
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

// A server error from the token endpoint is retried on the certificate already
// in hand. It is distinct from the re-mint path, which reacts to a certificate
// Entra has rejected: a 503 says nothing about the certificate, so minting a
// new one would be wasted work against a service that is already struggling.
func TestIMDSv2RetriesTheTokenLegOnAServerError(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	fake.tokenFailures = 1
	fake.tokenFailureCode = http.StatusServiceUnavailable
	fake.tokenFailureBody = `{"error":"temporarily_unavailable"}`

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if got := strings.Join(fake.calls, ","); got != "metadata,issue,token,token" {
		t.Errorf("calls = %q, want the token request retried without a new certificate", got)
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

	// The v1 endpoint is not redirectable by environment variable, so the
	// request is intercepted at the transport instead. Recording it is what
	// makes this test meaningful: asserting only that the v2 legs were skipped
	// would also pass if the acquisition failed outright.
	var requested []string
	client, err := New(SystemAssigned(), WithHTTPClient(&http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			requested = append(requested, r.URL.String())
			body := `{"access_token":"v1-access-token","token_type":"Bearer","expires_on":"` +
				strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) +
				`","resource":"https://vault.azure.net","client_id":"c"}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    r,
			}, nil
		}),
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := client.AcquireToken(context.Background(), "https://vault.azure.net")
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if result.AccessToken != "v1-access-token" {
		t.Fatalf("access token = %q, want the IMDSv1 token", result.AccessToken)
	}
	if result.BindingCertificate != nil {
		t.Fatal("a plain acquisition returned a binding certificate")
	}
	if len(requested) != 1 {
		t.Fatalf("requests = %v, want exactly one IMDSv1 token request", requested)
	}
	if !strings.Contains(requested[0], "api-version=2018-02-01") {
		t.Fatalf("request = %q, want the IMDSv1 token endpoint", requested[0])
	}
	for _, url := range requested {
		if strings.Contains(url, "cred-api-version") || strings.Contains(url, "issuecredential") {
			t.Fatalf("a plain acquisition used an IMDSv2 endpoint: %s", url)
		}
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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
