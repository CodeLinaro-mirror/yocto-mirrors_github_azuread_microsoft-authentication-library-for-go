// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package managedidentity_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

// Acquire a certificate-bound (mtls_pop) token for a managed identity. The binding key is minted
// inside Virtualization-Based Security, so its private material never enters this process.
func ExampleWithMtlsProofOfPossession() {
	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.AcquireToken(context.TODO(), "https://vault.azure.net",
		mi.WithMtlsProofOfPossession())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result.Metadata.TokenType) // "mtls_pop"
	_ = result.BindingCertificate          // the certificate the token is bound to
}

// A bound token is only accepted when the same certificate is presented on the TLS handshake, so the
// binding certificate has to go into the transport used to call the resource.
func ExampleWithMtlsProofOfPossession_callingTheResource() {
	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.AcquireToken(context.TODO(), "https://vault.azure.net",
		mi.WithMtlsProofOfPossession())
	if err != nil {
		log.Fatal(err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{*result.BindingCertificate},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}

	req, err := http.NewRequest(http.MethodGet,
		"https://myvault.vault.azure.net/secrets/mysecret?api-version=7.4", nil)
	if err != nil {
		log.Fatal(err)
	}
	// The scheme is mtls_pop, not Bearer. A resource that enforces binding rejects the token if it
	// arrives as Bearer or over a connection that did not present the certificate.
	req.Header.Set("Authorization", "mtls_pop "+result.AccessToken)
	req.Header.Set("x-ms-tokenboundauth", "true")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
}

// WithRequestOverMtls authenticates the transport with the same certificate but asks for an ordinary
// bearer token, for resources that do not understand mtls_pop.
func ExampleWithRequestOverMtls() {
	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.AcquireToken(context.TODO(), "https://vault.azure.net",
		mi.WithRequestOverMtls())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result.Metadata.TokenType) // "Bearer" — not bound to the certificate
}

// Binding failures are typed, so a caller can tell "this host cannot do it" from "this call was
// wrong". There is deliberately no silent downgrade to an unbound token.
func Example_handlingUnsupportedHosts() {
	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		log.Fatal(err)
	}

	_, err = client.AcquireToken(context.TODO(), "https://vault.azure.net",
		mi.WithMtlsProofOfPossession())
	switch {
	case errors.Is(err, mi.ErrMtlsNotSupportedForPlatform):
		fmt.Println("not Windows: no KeyGuard available")
	case errors.Is(err, mi.ErrCredentialGuardNotAvailable):
		fmt.Println("Credential Guard/VBS is not enabled on this host")
	case errors.Is(err, mi.ErrMtlsPoPNotSupportedInIMDSv1):
		fmt.Println("this host serves IMDSv1 only")
	case errors.Is(err, mi.ErrMtlsPoPNotSupportedForSource):
		fmt.Println("this identity source has no v2 credential endpoint")
	case err != nil:
		log.Fatal(err)
	}
}
