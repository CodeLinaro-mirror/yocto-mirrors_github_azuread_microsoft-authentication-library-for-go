// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto"
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
const bindingKeyName = "com.microsoft.msal-go.imdsv2-binding-key"

// imdsV2 carries everything the IMDSv2 legs need. It is split out from Client so
// the IMDS calls can be exercised against a test server without constructing a
// full managed identity client.
type imdsV2 struct {
	httpClient  ops.HTTPClient
	keyProvider keyProvider
	miType      ID
	// baseEndpoint is the IMDS root. It is a field so tests can point the two
	// plain-HTTP legs at a local server.
	baseEndpoint string
}

// TEMPORARY DIAGNOSTIC - REVERT BEFORE PR.
var debugMetadataBody []byte

// TEMPORARY DIAGNOSTIC - REVERT BEFORE PR.
var (
	debugAttestation  string
	debugResponseBody []byte
)

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
	debugResponseBody = body // TEMPORARY DIAGNOSTIC - REVERT BEFORE PR.
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

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return csrMetadata{}, fmt.Errorf("managedidentity: requesting platform metadata: %w", err)
	}
	// A host that serves IMDSv1 only has no platform metadata endpoint at all.
	// That is a capability answer rather than a transient failure, so it is
	// reported as such instead of being retried.
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
	debugMetadataBody = body // TEMPORARY DIAGNOSTIC - REVERT BEFORE PR.

	var metadata csrMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return csrMetadata{}, fmt.Errorf("managedidentity: parsing platform metadata: %w", err)
	}
	if err := metadata.validate(); err != nil {
		return csrMetadata{}, err
	}
	return metadata, nil
}

// TEMPORARY DIAGNOSTIC - REVERT BEFORE PR.
//
// The service rejects the attested request with a message too general to act
// on, so this replays it with one variable changed at a time. The csr-only
// control is the important one: it distinguishes "the CSR stopped being
// acceptable" from "the attestation token is what is being rejected".
func (v imdsV2) debugProbeVariants(ctx context.Context, correlationID, csr, attestationToken string) string {
	target, err := v.endpoint(imdsV2IssueCredentialPath)
	if err != nil {
		return "probe: " + err.Error()
	}
	send := func(label, contentType string, body []byte) string {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(string(body)))
		if err != nil {
			return fmt.Sprintf("%s=<build failed: %v>", label, err)
		}
		setIMDSHeaders(req, correlationID)
		req.Header.Set("Content-Type", contentType)
		resp, err := v.httpClient.Do(req)
		if err != nil {
			return fmt.Sprintf("%s=<send failed: %v>", label, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusOK {
			return fmt.Sprintf("%s=200_OK(len=%d)", label, len(raw))
		}
		return fmt.Sprintf("%s=%d:%s", label, resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	csrOnly, _ := json.Marshal(certificateRequestBody{CSR: csr})
	attested, _ := json.Marshal(certificateRequestBody{CSR: csr, AttestationToken: attestationToken})
	camel, _ := json.Marshal(map[string]string{"csr": csr, "attestationToken": attestationToken})

	return strings.Join([]string{
		send("csrOnly", "application/json", csrOnly),
		send("attestedUtf8", "application/json; charset=utf-8", attested),
		send("camelCaseField", "application/json", camel),
	}, " || ")
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
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return certificateRequestResponse{}, fmt.Errorf("managedidentity: requesting a credential: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return certificateRequestResponse{}, ErrMtlsPoPNotSupportedInIMDSv1
	}
	if err := validateIMDSServerHeader(resp); err != nil {
		resp.Body.Close()
		return certificateRequestResponse{}, err
	}
	body, err := readIMDSResponse(resp)
	if err != nil {
		// TEMPORARY DIAGNOSTIC - REVERT BEFORE PR.
		probe := ""
		if attestationToken != "" {
			probe = v.debugProbeVariants(ctx, correlationID, csr, attestationToken)
		}
		return certificateRequestResponse{}, fmt.Errorf(
			"%w\n===IMDSV2-DIAG===\nMETADATA: %s\nRAWRESPONSE: %s\nPROBE: %s\nATTESTATION: %s\nCSR_B64: %s\n===END-DIAG===",
			err, string(debugMetadataBody), string(debugResponseBody), probe, debugAttestation, csr)
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
type bindingCertificate struct {
	TLS      tls.Certificate
	Leaf     *x509.Certificate
	ClientID string
	TenantID string
	Endpoint string
	// close releases the operating system handle behind the private key.
	close func() error
}

// Close releases the binding key.
func (b *bindingCertificate) Close() error {
	if b == nil || b.close == nil {
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
		close:    key.Close,
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

// mtlsHTTPClient returns a client that presents the binding certificate. A new
// client is built per binding certificate so that replacing the certificate
// cannot reuse a pooled connection authenticated with the previous one.
func mtlsHTTPClient(cert tls.Certificate) *http.Client {
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
func requestEntraToken(ctx context.Context, client *http.Client, binding *bindingCertificate, resource string, popRequested bool) (accesstokens.TokenResponse, error) {
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
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return accesstokens.TokenResponse{}, fmt.Errorf("managedidentity: building the token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
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
func scopeForResource(resource string) string {
	resource = strings.TrimSuffix(resource, "/.default")
	return resource + "/.default"
}
