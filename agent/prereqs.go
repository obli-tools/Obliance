package main

// Windows NT 6.x prerequisites, reported in the push body as `prereqs`
// by agents running on Windows 7 / 8.1 / Server 2008 R2 / 2012 / 2012 R2
// (omitted elsewhere). Cheap registry / export checks, cached
// (prereqs_windows.go); the mapping rules below are platform-independent and
// unit-tested.
//
//	sp1           Windows 7 / 2008 R2 only: Service Pack 1 (build 7601).
//	              Omitted on 6.2+ (no service pack there).
//	sha2Signing   SHA-2 Authenticode / update signing support: KB4474419 or
//	              KB3033929 installed (6.0 / 6.1); native from 6.2.
//	sha2Kbs       which of those KBs the servicing store lists.
//	kb2533623     SetDefaultDllDirectories available (KB2533623 or its
//	              successor KB3063858; native from 6.2) — needed by modern
//	              installers / runtimes.
//	tls12Schannel TLS 1.2 enabled for Schannel CLIENTS (PowerShell, .NET,
//	              WinHTTP, BITS...; the agent itself uses Go's TLS). Off by
//	              default on 6.0 / 6.1 unless SCHANNEL\Protocols\TLS 1.2\Client
//	              enables it; on by default from 6.2 unless disabled there.
//	wmfVersion    Windows PowerShell / WMF engine version ("2.0", "5.1...").
//	dotnet4x      highest .NET Framework 4.x ("4.8", "4.5.2", "4.0", "").

import (
	"errors"
	"syscall"
)

// NT6Prereqs is the push-body `prereqs` object.
type NT6Prereqs struct {
	SP1           *bool    `json:"sp1,omitempty"`
	SHA2Signing   bool     `json:"sha2Signing"`
	SHA2KBs       []string `json:"sha2Kbs,omitempty"`
	KB2533623     bool     `json:"kb2533623"`
	TLS12Schannel bool     `json:"tls12Schannel"`
	WMFVersion    string   `json:"wmfVersion,omitempty"`
	DotNet4x      string   `json:"dotnet4x"`
}

// sha2SigningKBs: the standalone updates that bring SHA-2 code signing
// support to Windows 7 / 2008 R2 (KB3033929: SHA-256 Authenticode
// verification, 2015; KB4474419: SHA-2 only update signing, 2019). Both are
// standalone packages (not part of the monthly rollups), so they show up in
// the servicing store as Package_for_KB<n>~...
var sha2SigningKBs = []string{"KB4474419", "KB3033929"}

// sha2SigningSupported: native from Windows 8 / 2012 (6.2), else one of the KBs.
func sha2SigningSupported(major, minor uint32, kbs []string) bool {
	if major > 6 || (major == 6 && minor >= 2) {
		return true
	}
	return len(kbs) > 0
}

// tls12ClientEnabled evaluates SCHANNEL\Protocols\TLS 1.2\Client:
// enabled / disabledByDefault are nil when the value is absent.
func tls12ClientEnabled(major, minor uint32, enabled, disabledByDefault *uint64) bool {
	if enabled != nil && *enabled == 0 {
		return false
	}
	if disabledByDefault != nil {
		return *disabledByDefault == 0
	}
	if major == 6 && minor <= 1 {
		// Windows 7 / 2008 R2: TLS 1.2 client is off unless enabled explicitly
		// (both values set as KB3140245 / Microsoft's guidance describes).
		return enabled != nil && *enabled != 0
	}
	return true
}

// dotNet4VersionFromRelease maps NDP\v4\Full "Release" to the product
// version (Microsoft's documented minimums). hasV4 = the v4\Full key exists
// (4.0 has no Release value).
func dotNet4VersionFromRelease(release uint64, hasV4 bool) string {
	switch {
	case release >= 533320:
		return "4.8.1"
	case release >= 528040:
		return "4.8"
	case release >= 461808:
		return "4.7.2"
	case release >= 461308:
		return "4.7.1"
	case release >= 460798:
		return "4.7"
	case release >= 394802:
		return "4.6.2"
	case release >= 394254:
		return "4.6.1"
	case release >= 393295:
		return "4.6"
	case release >= 379893:
		return "4.5.2"
	case release >= 378675:
		return "4.5.1"
	case release >= 378389:
		return "4.5"
	case hasV4:
		return "4.0"
	}
	return ""
}

// WinVerifyTrust results seen on Windows 7 / 2008 R2 WITHOUT SHA-2 code
// signing support when the file is signed with SHA-256 only.
const (
	trustEBadDigest   = 0x80096010 // TRUST_E_BAD_DIGEST
	nteBadAlgID       = 0x80090008 // NTE_BAD_ALGID
	trustENoSignature = 0x800B0100 // TRUST_E_NOSIGNATURE (unparsable SHA-2 signature)
	trustESysError    = 0x80096001 // TRUST_E_SYSTEM_ERROR
)

// isLikelySHA2SupportError: a signature failure that, on a system without
// SHA-2 support, means "cannot verify SHA-2" rather than "bad file".
func isLikelySHA2SupportError(err error) bool {
	var en syscall.Errno
	if !errors.As(err, &en) {
		return false
	}
	switch uint32(en) {
	case trustEBadDigest, nteBadAlgID, trustENoSignature, trustESysError:
		return true
	}
	return false
}

// sha2UnsupportedDetail is the orError detail of code "sha2_unsupported".
const sha2UnsupportedDetail = "this Windows cannot verify SHA-2 (SHA-256) Authenticode signatures: install KB4474419 and KB3033929 (SHA-2 code signing support), then retry"

// signatureFailureCode picks the orError code of a non-chain WinVerifyTrust
// failure: "sha2_unsupported" only when the file DOES carry an embedded
// signature (a truly unsigned file stays "signature_invalid"), the error is
// one an SHA-2-less Windows returns, and the SHA-2 KBs are missing.
func signatureFailureCode(trustErr error, hasEmbeddedSignature, sha2Missing bool) string {
	if hasEmbeddedSignature && sha2Missing && isLikelySHA2SupportError(trustErr) {
		return "sha2_unsupported"
	}
	return "signature_invalid"
}
