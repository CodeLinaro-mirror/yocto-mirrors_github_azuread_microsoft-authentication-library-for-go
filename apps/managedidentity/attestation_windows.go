// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// attestationLibName is loaded through the standard search order rather than a
// fixed path: the module cannot redistribute it, so it is found next to the
// host executable or wherever the deployment put it.
const attestationLibName = "AttestationClientLib.dll"

// attestationLogInfo mirrors the AttestationLogInfo struct the native library
// expects: a callback and an opaque context pointer.
type attestationLogInfo struct {
	log uintptr
	ctx uintptr
}

// nativeLogLevel values as the native library defines them.
var nativeLogLevels = [...]string{"error", "warn", "info", "debug"}

// procSearchPathW locates a module on the loader search path without loading
// it. x/sys/windows does not expose SearchPath, so it is bound here.
var procSearchPathW = windows.NewLazySystemDLL("kernel32.dll").NewProc("SearchPathW")

type attestationLib struct {
	attestKeyGuardImportKey *windows.LazyProc
	freeAttestationToken    *windows.LazyProc
}

var (
	attestationLibOnce sync.Once
	attestationLibVal  *attestationLib
	attestationLibErr  error
)

// attestationLog collects what the native library reports. The library is a
// black box whose failures are otherwise a bare integer, so its own diagnostics
// are the only way to tell an MAA policy denial from a missing TPM.
var attestationLog struct {
	mu    sync.Mutex
	lines []string
}

func recordAttestationLog(line string) {
	attestationLog.mu.Lock()
	defer attestationLog.mu.Unlock()
	// Bounded so a chatty library cannot grow this without limit.
	if len(attestationLog.lines) >= 256 {
		return
	}
	attestationLog.lines = append(attestationLog.lines, line)
}

func drainAttestationLog() []string {
	attestationLog.mu.Lock()
	defer attestationLog.mu.Unlock()
	out := attestationLog.lines
	attestationLog.lines = nil
	return out
}

// attestationLogThunk is the native logging callback. The pointer arguments are
// declared as *byte rather than uintptr so no uintptr is ever reinterpreted as
// a pointer, which is both unsafe and something go vet correctly rejects.
func attestationLogThunk(ctx uintptr, tag *byte, level uintptr, function *byte, line uintptr, message *byte) uintptr {
	levelName := "unknown"
	if int32(level) >= 0 && int(int32(level)) < len(nativeLogLevels) {
		levelName = nativeLogLevels[int32(level)]
	}
	recordAttestationLog(fmt.Sprintf("[%s] %s %s:%d %s",
		levelName,
		windows.BytePtrToString(tag),
		windows.BytePtrToString(function),
		int32(line),
		windows.BytePtrToString(message)))
	return 0
}

// loadAttestationLib resolves the native library once. A missing library is
// reported as errAttestationUnavailable so the caller can fall back, while a
// library that is present but unusable produces a real error.
func loadAttestationLib() (*attestationLib, error) {
	attestationLibOnce.Do(func() {
		dll := windows.NewLazyDLL(attestationLibName)
		if err := dll.Load(); err != nil {
			// A failed load reports ERROR_MOD_NOT_FOUND whether the library
			// itself is absent or one of its own dependencies is, so the error
			// alone cannot tell a host that never deployed it from a host that
			// deployed it without the Visual C++ runtime it links against.
			// Locating the file separates the two: only the first case is a
			// fallback, because silently downgrading a deployment that meant to
			// attest would resurface as an unexplained rejection from IMDS.
			if path, findErr := findAttestationLib(); findErr == nil {
				attestationLibErr = fmt.Errorf("loading %s: %v; the library is present but could not be loaded, which usually means a dependency is missing, such as the Visual C++ runtime (MSVCP140.dll, VCRUNTIME140.dll)", path, err)
				return
			}
			attestationLibErr = fmt.Errorf("%w: loading %s: %v", errAttestationUnavailable, attestationLibName, err)
			return
		}
		initLib := dll.NewProc("InitAttestationLib")
		attest := dll.NewProc("AttestKeyGuardImportKey")
		free := dll.NewProc("FreeAttestationToken")
		for _, p := range []*windows.LazyProc{initLib, attest, free} {
			if err := p.Find(); err != nil {
				attestationLibErr = fmt.Errorf("%w: %s is missing %s: %v", errAttestationUnavailable, attestationLibName, p.Name, err)
				return
			}
		}

		info := attestationLogInfo{log: windows.NewCallback(attestationLogThunk)}
		if r, _, err := syscall.SyscallN(initLib.Addr(), uintptr(unsafe.Pointer(&info))); r != 0 {
			attestationLibErr = fmt.Errorf("managedidentity: InitAttestationLib returned %d: %v", int32(r), err)
			return
		}
		// info holds a pointer to a Go callback for the lifetime of the process.
		// The library is deliberately never uninitialised: doing so would race
		// with any in-flight attestation on another goroutine, and the process
		// exiting reclaims it anyway.
		attestationLibVal = &attestationLib{attestKeyGuardImportKey: attest, freeAttestationToken: free}
	})
	return attestationLibVal, attestationLibErr
}

// findAttestationLib locates the library on the loader search path without
// loading it, so a load failure caused by a missing dependency can be told
// apart from the library simply not being deployed.
func findAttestationLib() (string, error) {
	name, err := windows.UTF16PtrFromString(attestationLibName)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_PATH)
	n, _, err := syscall.SyscallN(procSearchPathW.Addr(),
		0,
		uintptr(unsafe.Pointer(name)),
		0,
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&buf[0])),
		0)
	if n == 0 {
		return "", err
	}
	if n > uintptr(len(buf)) {
		buf = make([]uint16, n)
		if n, _, err = syscall.SyscallN(procSearchPathW.Addr(),
			0,
			uintptr(unsafe.Pointer(name)),
			0,
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&buf[0])),
			0); n == 0 {
			return "", err
		}
	}
	return windows.UTF16ToString(buf), nil
}

// attestKeyGuard asks the native library for an MAA statement over key. It
// returns errAttestationUnavailable when the library is not deployed, which the
// caller treats as "send a non-attested request" rather than as a failure.
func attestKeyGuard(endpoint, clientID string, key bindingKey) (string, error) {
	// Only a VBS-isolated key can be attested. MSAL .NET gates on the same
	// condition and sends a non-attested request for software and TPM keys,
	// because MAA has nothing to vouch for when the private material never
	// entered a trustlet.
	if key.Type != keyTypeKeyGuard {
		return "", fmt.Errorf("%w: the binding key is not KeyGuard-isolated", errAttestationUnavailable)
	}
	signer, ok := key.Signer.(*ncryptSigner)
	if !ok {
		return "", fmt.Errorf("%w: the binding key is not a CNG key", errAttestationUnavailable)
	}
	lib, err := loadAttestationLib()
	if err != nil {
		return "", err
	}

	endpointPtr, err := windows.BytePtrFromString(endpoint)
	if err != nil {
		return "", fmt.Errorf("managedidentity: the attestation endpoint is not usable: %w", err)
	}
	clientIDPtr, err := windows.BytePtrFromString(clientID)
	if err != nil {
		return "", fmt.Errorf("managedidentity: the client ID is not usable: %w", err)
	}

	signer.mu.Lock()
	handle := signer.key
	closed := signer.closed
	signer.mu.Unlock()
	if closed || handle == 0 {
		return "", fmt.Errorf("managedidentity: the binding key handle is already released")
	}

	drainAttestationLog()
	// token is a *byte rather than a uintptr so the returned C string is never
	// reconstructed from an integer.
	var token *byte
	// authToken and clientPayload are null: the library fetches its own managed
	// identity token from IMDS, which is what MSAL .NET passes too.
	r, _, callErr := syscall.SyscallN(lib.attestKeyGuardImportKey.Addr(),
		uintptr(unsafe.Pointer(endpointPtr)),
		0,
		0,
		uintptr(handle),
		uintptr(unsafe.Pointer(&token)),
		uintptr(unsafe.Pointer(clientIDPtr)),
	)
	// Keep the argument memory alive across the call.
	runtime.KeepAlive(endpointPtr)
	runtime.KeepAlive(clientIDPtr)

	if code := int32(r); code != 0 || token == nil {
		detail := strings.Join(drainAttestationLog(), "; ")
		if detail == "" {
			detail = "the native library reported no detail"
		}
		return "", fmt.Errorf("managedidentity: KeyGuard attestation failed with native code %d (%v): %s", code, callErr, detail)
	}
	jwt := windows.BytePtrToString(token)
	_, _, _ = syscall.SyscallN(lib.freeAttestationToken.Addr(), uintptr(unsafe.Pointer(token)))
	if jwt == "" {
		return "", fmt.Errorf("managedidentity: KeyGuard attestation produced an empty token: %s",
			strings.Join(drainAttestationLog(), "; "))
	}
	// TEMPORARY DIAGNOSTIC - REVERT BEFORE PR.
	debugAttestation = describeAttestationToken(jwt)
	return jwt, nil
}

// describeAttestationToken summarises a token without disclosing it.
// TEMPORARY DIAGNOSTIC - REVERT BEFORE PR.
func describeAttestationToken(jwt string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "len=%d segments=%d", len(jwt), len(strings.Split(jwt, ".")))
	parts := strings.Split(jwt, ".")
	for i, name := range []string{"header", "payload"} {
		if i >= len(parts) {
			break
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			fmt.Fprintf(&b, " %s=<undecodable: %v>", name, err)
			continue
		}
		if name == "payload" {
			// Report only the claim names and a few non-sensitive values; the
			// claim set itself carries machine identity.
			var claims map[string]json.RawMessage
			if err := json.Unmarshal(raw, &claims); err != nil {
				fmt.Fprintf(&b, " payload=<unparsable: %v>", err)
				continue
			}
			names := make([]string, 0, len(claims))
			for k := range claims {
				names = append(names, k)
			}
			sort.Strings(names)
			fmt.Fprintf(&b, " payloadClaims=%v", names)
			for _, k := range []string{"iss", "x-ms-attestation-type", "x-ms-isolation-tee"} {
				if v, ok := claims[k]; ok {
					fmt.Fprintf(&b, " %s=%s", k, string(v))
				}
			}
			continue
		}
		fmt.Fprintf(&b, " %s=%s", name, string(raw))
	}
	if logs := drainAttestationLog(); len(logs) > 0 {
		if len(logs) > 12 {
			logs = logs[len(logs)-12:]
		}
		fmt.Fprintf(&b, " nativeLog=[%s]", strings.Join(logs, " | "))
	}
	return b.String()
}
