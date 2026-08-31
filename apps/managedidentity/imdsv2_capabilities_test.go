// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// authParamsForTest returns parameters carrying no cache components, so a test
// can observe exactly what stamping adds.
func authParamsForTest() authority.AuthParams {
	return authority.AuthParams{ClientID: "client", Scopes: []string{"https://vault.azure.net"}}
}

// The numbering is a contract with MSAL .NET, not an implementation detail: the
// two libraries describe the same host to the same callers, and the gap at 2 is
// reserved for a tier neither of them defines yet.
func TestMtlsBindingStrengthValues(t *testing.T) {
	for _, test := range []struct {
		strength MtlsBindingStrength
		value    int
		name     string
	}{
		{MtlsBindingStrengthNone, 0, "None"},
		{MtlsBindingStrengthSoftware, 1, "Software"},
		{MtlsBindingStrengthKeyGuard, 3, "KeyGuard"},
	} {
		if int(test.strength) != test.value {
			t.Fatalf("%s = %d, want %d", test.name, int(test.strength), test.value)
		}
		if test.strength.String() != test.name {
			t.Fatalf("String() = %q, want %q", test.strength.String(), test.name)
		}
	}
	if MtlsBindingStrengthSoftware >= MtlsBindingStrengthKeyGuard {
		t.Fatal("the tiers must order weakest to strongest, or a floor comparison is meaningless")
	}
}

// A host that answers the CSR metadata call speaks the key-bound protocol, and
// a VBS key is what raises it from the software floor to the attested tier.
func TestCapabilitiesReportsKeyGuardOnAttestableHost(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if capabilities.Source != DefaultToIMDS {
		t.Fatalf("Source = %q, want %q", capabilities.Source, DefaultToIMDS)
	}
	if capabilities.MaxSupportedBindingStrength != MtlsBindingStrengthKeyGuard {
		t.Fatalf("strength = %s, want KeyGuard", capabilities.MaxSupportedBindingStrength)
	}
	if !capabilities.IsMtlsPoPSupportedByHost() {
		t.Fatal("a host that can produce a KeyGuard key supports PoP")
	}
	if capabilities.ErrorReason != "" {
		t.Fatalf("ErrorReason = %q, want empty on a detected host", capabilities.ErrorReason)
	}
}

// A key that cannot be provisioned right now is a local condition. The host has
// already proved it speaks v2, so reporting None would tell a credential chain
// to abandon managed identity over something transient.
func TestCapabilitiesKeepsSoftwareFloorWhenKeyProviderFails(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	provider.err = errors.New("no VBS on this host")

	client := fake.newTestClient(t, SystemAssigned(), provider)
	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if capabilities.MaxSupportedBindingStrength != MtlsBindingStrengthSoftware {
		t.Fatalf("strength = %s, want Software", capabilities.MaxSupportedBindingStrength)
	}
}

// A host that does not answer the CSR metadata call cannot bind anything, and
// the reason it gave is worth keeping: it is what a caller has to act on.
func TestCapabilitiesReportsNoneWhenMetadataUnavailable(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.metadataStatus = 404
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if capabilities.MaxSupportedBindingStrength != MtlsBindingStrengthNone {
		t.Fatalf("strength = %s, want None", capabilities.MaxSupportedBindingStrength)
	}
	if capabilities.IsMtlsPoPSupportedByHost() {
		t.Fatal("a host with no v2 endpoint does not support PoP")
	}
	if capabilities.ErrorReason == "" {
		t.Fatal("the reason discovery failed should be reported, it is what a caller acts on")
	}
}

// Discovery probes the metadata service and provisions a key. Neither changes
// while the process runs, so a service resolving credentials on many goroutines
// must not pay for it repeatedly.
func TestCapabilitiesIsDiscoveredOnce(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.Capabilities(context.Background()); err != nil {
		t.Fatalf("first Capabilities: %v", err)
	}
	probes := fake.countOf("metadata")
	for i := 0; i < 5; i++ {
		if _, err := client.Capabilities(context.Background()); err != nil {
			t.Fatalf("Capabilities: %v", err)
		}
	}
	if fake.countOf("metadata") != probes {
		t.Fatalf("probed %d times, want %d: discovery should be cached for the process", fake.countOf("metadata"), probes)
	}
}

// A cancelled call must not publish its result, or one cancellation would be
// remembered as the host's answer for the rest of the process.
func TestCapabilitiesDoesNotCacheCancelledResult(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Capabilities(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Capabilities on a cancelled context = %v, want context.Canceled", err)
	}

	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities after cancellation: %v", err)
	}
	if capabilities.MaxSupportedBindingStrength != MtlsBindingStrengthKeyGuard {
		t.Fatalf("strength = %s, want KeyGuard: the cancelled call must not have been cached",
			capabilities.MaxSupportedBindingStrength)
	}
}

// A floor the host meets is invisible; the acquisition proceeds normally.
func TestMinStrengthAllowsHostThatMeetsIt(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithMtlsPoPMinStrength(MtlsBindingStrengthKeyGuard)); err != nil {
		t.Fatalf("AcquireToken under a floor the host meets: %v", err)
	}
}

// A floor the host cannot meet fails before IMDS is asked for a credential the
// caller would have refused.
func TestMinStrengthRejectsHostBelowFloor(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	provider.typ = keyTypeSoftware

	client := fake.newTestClient(t, SystemAssigned(), provider)
	fake.resetCalls()
	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithMtlsPoPMinStrength(MtlsBindingStrengthKeyGuard))
	if !errors.Is(err, ErrMinStrengthNotMet) {
		t.Fatalf("AcquireToken = %v, want ErrMinStrengthNotMet", err)
	}
	if !strings.Contains(err.Error(), "Software") || !strings.Contains(err.Error(), "KeyGuard") {
		t.Fatalf("error %q should name both what the host offers and what was required", err)
	}
	if fake.countOf("issue") != 0 {
		t.Fatal("a credential was requested for an acquisition that could never have succeeded")
	}
}

// No floor means no discovery: a caller who never asked for one must not pay
// for a probe.
func TestMinStrengthNoneSkipsDiscovery(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithMtlsPoPMinStrength(MtlsBindingStrengthNone)); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	capabilitiesCache.mu.Lock()
	cached := capabilitiesCache.result
	capabilitiesCache.mu.Unlock()
	if cached != nil {
		t.Fatal("discovery ran for a request that imposed no floor")
	}
}

// A floor is a statement about the key a token is bound to, so it cannot be
// honoured by a request that binds none.
func TestMinStrengthRequiresMtls(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsPoPMinStrength(MtlsBindingStrengthKeyGuard))
	if !errors.Is(err, ErrMinStrengthRequiresMtls) {
		t.Fatalf("AcquireToken = %v, want ErrMinStrengthRequiresMtls", err)
	}
}

// A token acquired under a floor was checked against a guarantee one acquired
// without a floor was not, so raising the floor must not be satisfiable by a
// token cached before it was set.
func TestCacheComponentsPartitionByMinStrength(t *testing.T) {
	base := authParamsForTest()
	AcquireTokenOptions{}.stampCacheComponents(&base)
	none := base.CacheExtKeyGenerator()

	floored := authParamsForTest()
	AcquireTokenOptions{minStrength: MtlsBindingStrengthKeyGuard}.stampCacheComponents(&floored)
	if floored.CacheExtKeyGenerator() == none {
		t.Fatal("a floored request shares a cache entry with an unfloored one")
	}

	software := authParamsForTest()
	AcquireTokenOptions{minStrength: MtlsBindingStrengthSoftware}.stampCacheComponents(&software)
	if software.CacheExtKeyGenerator() == floored.CacheExtKeyGenerator() {
		t.Fatal("two different floors share a cache entry")
	}
}

// Requesting no floor must leave the key exactly as it was before the option
// existed, or every token cached by an earlier version is orphaned.
func TestCacheComponentsUnchangedWithoutOptions(t *testing.T) {
	params := authParamsForTest()
	AcquireTokenOptions{}.stampCacheComponents(&params)
	if got := params.CacheExtKeyGenerator(); got != "" {
		t.Fatalf("CacheExtKeyGenerator = %q, want empty: a plain request must keep the legacy key shape", got)
	}
}

// A bearer token obtained over mTLS is issued under a different policy than one
// obtained over plain HTTP, so the two must not share an entry.
func TestCacheComponentsPartitionBearerOverMtls(t *testing.T) {
	plain := authParamsForTest()
	AcquireTokenOptions{}.stampCacheComponents(&plain)

	overMtls := authParamsForTest()
	AcquireTokenOptions{overMtls: true}.stampCacheComponents(&overMtls)
	if overMtls.CacheExtKeyGenerator() == plain.CacheExtKeyGenerator() {
		t.Fatal("a bearer token acquired over mTLS shares a cache entry with an ordinary one")
	}
}

// Stamping runs on every acquisition against the same params, so an option that
// is no longer set has to be removed rather than left behind.
func TestCacheComponentsClearedWhenOptionsDropped(t *testing.T) {
	params := authParamsForTest()
	AcquireTokenOptions{overMtls: true, minStrength: MtlsBindingStrengthKeyGuard}.stampCacheComponents(&params)
	if len(params.CacheKeyComponents) != 2 {
		t.Fatalf("components = %v, want both recorded", params.CacheKeyComponents)
	}
	AcquireTokenOptions{}.stampCacheComponents(&params)
	if len(params.CacheKeyComponents) != 0 {
		t.Fatalf("components = %v, want empty once the options are dropped", params.CacheKeyComponents)
	}
}

// A cached token is normally served without contacting the service. Force
// refresh is what a caller reaches for when something outside this library has
// changed what the token should contain.
func TestForceRefreshBypassesTokenCache(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	served := fake.countOf("token")

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if fake.countOf("token") != served {
		t.Fatalf("token requests = %d, want %d: the second call should have been served from the cache", fake.countOf("token"), served)
	}

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithForceRefresh()); err != nil {
		t.Fatalf("forced AcquireToken: %v", err)
	}
	if fake.countOf("token") != served+1 {
		t.Fatalf("token requests = %d, want %d: a forced refresh must reach the service", fake.countOf("token"), served+1)
	}
}

// The certificate identifies the machine and is unaffected by a token going
// stale. Re-minting one per forced call would be throttled by IMDS.
func TestForceRefreshKeepsBindingCertificate(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	issued := fake.countOf("issue")

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithForceRefresh()); err != nil {
		t.Fatalf("forced AcquireToken: %v", err)
	}
	if fake.countOf("issue") != issued {
		t.Fatalf("credential requests = %d, want %d: a forced token refresh must not re-mint the certificate",
			fake.countOf("issue"), issued)
	}
}
