// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import "errors"

// errAttestationUnavailable reports that this host cannot produce a KeyGuard
// attestation statement, which is different from producing one and having it
// rejected. Attestation depends on AttestationClientLib.dll, a native component
// that is distributed separately and is not part of this module.
//
// This only ever reaches a caller who asked for attestation with
// WithAttestationSupport(), and it is an error rather than a downgrade: having
// asked, the caller is not quietly handed a credential that lacks it. A caller
// who did not ask never attempts attestation and never sees this.
var errAttestationUnavailable = errors.New("managedidentity: KeyGuard attestation is not available on this host")

// attestKeyGuardFn is the attestation entry point, indirected through a variable
// so a test can supply a provider on a host without KeyGuard. MSAL .NET exposes
// an equivalent hook on PopKeyAttestor for the same reason.
var attestKeyGuardFn = attestKeyGuard
