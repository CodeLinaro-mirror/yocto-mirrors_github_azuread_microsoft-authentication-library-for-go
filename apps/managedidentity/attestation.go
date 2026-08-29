// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import "errors"

// errAttestationUnavailable reports that this host cannot produce a KeyGuard
// attestation statement, which is different from producing one and having it
// rejected. Attestation depends on AttestationClientLib.dll, a native component
// that is distributed separately and is not part of this module, so its absence
// is the ordinary case rather than a failure: the caller falls back to a
// non-attested credential request, exactly as MSAL .NET does when its optional
// Microsoft.Identity.Client.KeyAttestation package is not referenced.
//
// A resource that mandates attestation then rejects the request itself, which
// keeps the policy decision on the service where it belongs.
var errAttestationUnavailable = errors.New("managedidentity: KeyGuard attestation is not available on this host")
