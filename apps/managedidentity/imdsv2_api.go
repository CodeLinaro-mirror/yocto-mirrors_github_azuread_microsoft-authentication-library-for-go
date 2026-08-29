// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// WithMtlsHTTPClient overrides how the mutual-TLS client is built for the
// IMDSv2 token leg.
//
// The default client presents the binding certificate over TLS 1.2 or later,
// which is what almost every application wants. Supply a factory only when the
// TLS handshake has to be owned by the caller, for example to add a proxy or a
// custom root store. The factory receives the binding certificate and must
// return a client that presents it, otherwise the token request is rejected.
//
// This does not affect the two plain-HTTP calls to the metadata service, which
// use the client given to [WithHTTPClient].
func WithMtlsHTTPClient(factory func(cert tls.Certificate) *http.Client) ClientOption {
	return func(c *Client) {
		c.mtlsClientFactory = factory
	}
}

// WithMtlsProofOfPossession requests a certificate-bound access token
// (token_type=mtls_pop) instead of a bearer token.
//
// The token is bound to a short-lived certificate that Azure Instance Metadata
// Service issues to this virtual machine, whose private key is created inside
// Virtualization-based Security and never leaves it. A resource that supports
// bound tokens will reject the token if it is presented on a connection that
// does not use that certificate, so a stolen token is not usable elsewhere.
//
// The returned token must be sent over a connection authenticated with the same
// certificate. Use [AuthResult.MtlsHTTPClient] to obtain a client that does
// this, and present the token with the "mtls_pop" scheme rather than "Bearer".
//
// This requires Windows with Credential Guard enabled and a host that serves
// IMDSv2. It cannot be combined with [WithRequestOverMtls].
func WithMtlsProofOfPossession() AcquireTokenOption {
	return func(o *AcquireTokenOptions) {
		o.mtlsPoP = true
	}
}

// WithRequestOverMtls requests an ordinary bearer token, but obtains it over a
// mutually authenticated connection using the certificate IMDS issues to this
// virtual machine.
//
// This hardens acquisition without changing how the token is used: the result
// is a normal bearer token that any resource accepts. Use it when the resource
// does not support certificate-bound tokens but the acquisition path should
// still be bound to this machine.
//
// This requires Windows with Credential Guard enabled and a host that serves
// IMDSv2. It cannot be combined with [WithMtlsProofOfPossession].
func WithRequestOverMtls() AcquireTokenOption {
	return func(o *AcquireTokenOptions) {
		o.overMtls = true
	}
}

// usesIMDSv2 reports whether the options select the IMDSv2 certificate path.
func (o AcquireTokenOptions) usesIMDSv2() bool {
	return o.mtlsPoP || o.overMtls
}

// validate rejects option combinations that cannot be satisfied.
func (o AcquireTokenOptions) validate(source Source) error {
	if o.mtlsPoP && o.overMtls {
		return ErrMtlsPoPAndBearerExclusive
	}
	if !o.usesIMDSv2() {
		return nil
	}
	// Only the IMDS source issues binding certificates. The other sources have
	// no equivalent, and silently returning an ordinary bearer token would give
	// the caller a token with none of the protection they asked for.
	if source != DefaultToIMDS {
		return fmt.Errorf("%w: the source is %s", ErrMtlsPoPNotSupportedForSource, source)
	}
	if !platformSupportsMtlsPoP() {
		return ErrMtlsNotSupportedForPlatform
	}
	return nil
}

// acquireTokenForIMDSv2 runs the certificate-bound acquisition path.
//
// A cached certificate can be rejected by Entra without any local signal that
// it went stale, so a single re-mint and retry is attempted. The retry is
// bounded to one attempt: a second failure is a real error rather than a stale
// certificate, and retrying further would turn a misconfiguration into a loop
// against a rate-limited service.
func (c Client) acquireTokenForIMDSv2(ctx context.Context, resource string, o AcquireTokenOptions) (AuthResult, error) {
	v := imdsV2{
		httpClient:   c.httpClient,
		keyProvider:  c.bindingKeyProvider(),
		miType:       c.miType,
		baseEndpoint: imdsV2BaseEndpoint(),
	}

	binding, key, err := v.getBindingCertificate(ctx, o.attestation)
	if err != nil {
		return AuthResult{}, err
	}

	tr, err := requestEntraToken(ctx, c.mtlsClient(binding.TLS), binding, resource, o.mtlsPoP)
	if err != nil {
		if !shouldRemintCertificate(err) {
			return AuthResult{}, err
		}
		certCache.evict(key)
		binding, _, err = v.getBindingCertificate(ctx, o.attestation)
		if err != nil {
			return AuthResult{}, err
		}
		tr, err = requestEntraToken(ctx, c.mtlsClient(binding.TLS), binding, resource, o.mtlsPoP)
		if err != nil {
			return AuthResult{}, err
		}
	}

	if err := verifyTokenType(tr, o.mtlsPoP); err != nil {
		return AuthResult{}, err
	}
	return c.authResultForIMDSv2(tr, binding, o)
}

// verifyTokenType checks that the service returned the kind of token that was
// requested.
//
// Entra can answer a token_type=mtls_pop request with a bearer token, for
// example when the tenant has not enabled bound tokens. Returning that token
// would hand the caller an unbound credential while the call site believes it
// is bound, so it is rejected instead.
func verifyTokenType(tr accesstokens.TokenResponse, popRequested bool) error {
	if !popRequested {
		return nil
	}
	if !strings.EqualFold(tr.TokenType, authority.AccessTokenTypeMtlsPoP) {
		return fmt.Errorf(
			"managedidentity: a certificate-bound token was requested but the service returned a %q token; the tenant or resource may not support bound tokens",
			tr.TokenType)
	}
	return nil
}

// authResultForIMDSv2 converts the token response, caching bound tokens under a
// scheme keyed by the binding certificate so they cannot be confused with
// bearer tokens for the same resource.
func (c Client) authResultForIMDSv2(tr accesstokens.TokenResponse, binding *bindingCertificate, o AcquireTokenOptions) (AuthResult, error) {
	params := c.authParams
	if o.mtlsPoP {
		params.AuthnScheme = authority.NewMtlsPoPAuthenticationScheme(binding.Leaf)
	}
	res, err := authResultFromToken(params, tr)
	if err != nil {
		return AuthResult{}, err
	}
	if o.mtlsPoP {
		// The caller has to present this certificate when calling the resource,
		// otherwise the bound token is rejected. A copy is handed out so a
		// caller mutating it cannot corrupt the cached certificate that future
		// handshakes rely on.
		res.BindingCertificate = copyBindingCertificate(binding)
	}
	return res, nil
}

// copyBindingCertificate returns a certificate the caller can hold and mutate
// without affecting the cached one. The DER chain is deep-copied because the
// cached certificate is shared across concurrent acquisitions.
func copyBindingCertificate(binding *bindingCertificate) *tls.Certificate {
	chain := make([][]byte, len(binding.TLS.Certificate))
	for i, der := range binding.TLS.Certificate {
		chain[i] = append([]byte(nil), der...)
	}
	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  binding.TLS.PrivateKey,
		Leaf:        binding.Leaf,
	}
}

// mtlsClient builds the client used for the IMDSv2 token leg, honouring
// [WithMtlsHTTPClient] when the caller supplied a factory.
func (c Client) mtlsClient(cert tls.Certificate) *http.Client {
	if c.mtlsClientFactory != nil {
		return c.mtlsClientFactory(cert)
	}
	return mtlsHTTPClient(cert)
}

// imdsV2BaseEndpoint returns the metadata service root.
//
// AZURE_POD_IDENTITY_AUTHORITY_HOST redirects the metadata calls at a pod
// identity sidecar, which is how AKS presents a managed identity to a
// container. It is honoured here for the same reason IMDSv1 honours it.
func imdsV2BaseEndpoint() string {
	if host := os.Getenv(azurePodIdentityAuthorityHostEnvVar); host != "" {
		return strings.TrimSuffix(host, "/")
	}
	return imdsV2DefaultBaseEndpoint
}

// bindingKeyProvider returns the key provider for this client. It is
// indirected through a field so the flow tests can supply a software key.
func (c Client) bindingKeyProvider() keyProvider {
	if c.keyProvider != nil {
		return c.keyProvider
	}
	return newKeyProvider()
}
