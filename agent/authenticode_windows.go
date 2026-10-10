//go:build windows

package main

// Authenticode check of the ObliReach MSI before msiexec runs it.
//
//  1. WinVerifyTrust (WINTRUST_ACTION_GENERIC_VERIFY_V2, no UI, no revocation
//     check — offline/airgap friendly; cache-only URL retrieval in airgap).
//  2. The signer leaf certificate is read from the embedded PKCS#7
//     (CryptQueryObject → CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM) →
//     CertFindCertificateInStore(CERT_FIND_SUBJECT_CERT)).
//  3. Accepted when its raw Subject DN equals the Subject DN of the signer of
//     THIS agent's executable, or its simple display name equals the pinned
//     publisher (obliReachSignerPin). The subject, not the thumbprint, is
//     compared so a certificate renewal keeps working.
//  4. CERT_E_UNTRUSTEDROOT / CERT_E_CHAINING (e.g. an airgapped machine that
//     lacks the Certum root): accepted ONLY when the leaf is the very same
//     certificate (thumbprint) as this agent's own signer — a matching subject
//     is not enough there, anyone can self-sign that subject.

import (
	"bytes"
	"crypto/sha1"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// obliReachSignerPin is the accepted publisher besides "same subject as this
// agent's signer". Empty in source: the release build sets the publisher's
// certificate CN:
//
//	go build -ldflags "-X 'main.obliReachSignerPin=<certificate CN>'"
//
// Empty, only an MSI signed with the same subject as this agent is accepted.
var obliReachSignerPin = ""

const cmsgSignerInfoParam = 6 // CMSG_SIGNER_INFO_PARAM

var (
	modCrypt32           = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = modCrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = modCrypt32.NewProc("CryptMsgClose")
)

// cmsgSignerInfoHead is the leading part of CMSG_SIGNER_INFO (only the
// fields needed to find the signer certificate).
type cmsgSignerInfoHead struct {
	Version      uint32
	Issuer       windows.CertNameBlob
	SerialNumber windows.CryptIntegerBlob
}

type authenticodeSigner struct {
	subject    []byte   // raw DER Subject DN of the leaf
	name       string   // simple display name (CN)
	thumbprint [20]byte // SHA-1 of the encoded leaf certificate
}

var (
	ownSignerOnce sync.Once
	ownSigner     *authenticodeSigner
)

// verifyObliReachSigner is the production entry point used before msiexec.
func verifyObliReachSigner(path string) error {
	ownSignerOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			return
		}
		// Only a genuinely signed agent is a reference (an unsigned dev build
		// falls back to the pinned publisher).
		if trustErr := winVerifyTrustFile(exe, IsAirgapMode()); trustErr != nil && !isChainTrustError(trustErr) {
			return
		}
		if s, err := readAuthenticodeSigner(exe); err == nil {
			ownSigner = s
		}
	})
	return verifySignerAgainst(path, ownSigner, obliReachSignerPin, IsAirgapMode())
}

// verifySignerAgainst checks path's Authenticode signature and signer
// against a reference signer (may be nil) and a pinned publisher name.
func verifySignerAgainst(path string, ref *authenticodeSigner, pin string, cacheOnly bool) error {
	trustErr := winVerifyTrustFile(path, cacheOnly)
	chainOnly := false
	if trustErr != nil {
		if !isChainTrustError(trustErr) {
			// Windows 7 / 2008 R2 without KB4474419 / KB3033929 cannot verify a
			// SHA-256 signature at all: say so (actionable) instead of the
			// generic "signature_invalid" that suggests a tampered file.
			if isLikelySHA2SupportError(trustErr) && sha2SigningMissing() {
				_, sigErr := readAuthenticodeSigner(path)
				if signatureFailureCode(trustErr, sigErr == nil, true) == "sha2_unsupported" {
					return &orError{Code: "sha2_unsupported", Detail: fmt.Sprintf("%s: %s (%s)", filepath.Base(path), sha2UnsupportedDetail, trustErrorText(trustErr))}
				}
			}
			return &orError{Code: "signature_invalid", Detail: fmt.Sprintf("%s: %s", filepath.Base(path), trustErrorText(trustErr))}
		}
		chainOnly = true
	}
	leaf, err := readAuthenticodeSigner(path)
	if err != nil {
		return &orError{Code: "signature_invalid", Detail: "cannot read the signer certificate: " + err.Error()}
	}
	if chainOnly {
		if ref != nil && leaf.thumbprint == ref.thumbprint {
			return nil
		}
		return &orError{Code: "signature_untrusted_root",
			Detail: fmt.Sprintf("signer %q does not chain to a trusted root (%s)", truncateStr(leaf.name, 120), trustErrorText(trustErr))}
	}
	if ref != nil && len(ref.subject) > 0 && bytes.Equal(leaf.subject, ref.subject) {
		return nil
	}
	if pin != "" && leaf.name == pin {
		return nil
	}
	return &orError{Code: "signer_mismatch", Detail: fmt.Sprintf("signed by %q", truncateStr(leaf.name, 120))}
}

func isChainTrustError(err error) bool {
	var en syscall.Errno
	if !errors.As(err, &en) {
		return false
	}
	c := uint32(en)
	return c == uint32(windows.CERT_E_UNTRUSTEDROOT) || c == uint32(windows.CERT_E_CHAINING)
}

func trustErrorText(err error) string {
	var en syscall.Errno
	if errors.As(err, &en) {
		return fmt.Sprintf("0x%08X", uint32(en))
	}
	return err.Error()
}

// winVerifyTrustFile runs WinVerifyTrust on a file (embedded signature).
func winVerifyTrustFile(path string, cacheOnly bool) error {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	fileInfo := &windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: p16,
	}
	provFlags := uint32(windows.WTD_REVOCATION_CHECK_NONE)
	if cacheOnly {
		provFlags |= windows.WTD_CACHE_ONLY_URL_RETRIEVAL
	}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
		ProvFlags:                       provFlags,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	runtime.KeepAlive(fileInfo)
	return verifyErr
}

// readAuthenticodeSigner extracts the signer leaf certificate of a file's
// embedded Authenticode signature (works for PE files and MSIs).
func readAuthenticodeSigner(path string) (*authenticodeSigner, error) {
	if err := procCryptMsgGetParam.Find(); err != nil {
		return nil, err
	}
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var encoding, contentType, formatType uint32
	var store, msg windows.Handle
	if err := windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(p16),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, windows.CERT_QUERY_FORMAT_FLAG_BINARY, 0,
		&encoding, &contentType, &formatType, &store, &msg, nil); err != nil {
		return nil, fmt.Errorf("no embedded signature (%v)", err)
	}
	defer windows.CertCloseStore(store, 0)
	defer procCryptMsgClose.Call(uintptr(msg))

	var size uint32
	if r, _, e := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerInfoParam, 0, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
		return nil, fmt.Errorf("CryptMsgGetParam: %v", e)
	}
	if size < uint32(unsafe.Sizeof(cmsgSignerInfoHead{})) || size > 1<<20 {
		return nil, fmt.Errorf("unexpected signer info size %d", size)
	}
	buf := make([]uint64, (size+7)/8) // 8-byte aligned (the struct holds pointers)
	if r, _, e := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerInfoParam, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return nil, fmt.Errorf("CryptMsgGetParam: %v", e)
	}
	si := (*cmsgSignerInfoHead)(unsafe.Pointer(&buf[0]))
	var ci windows.CertInfo
	ci.Issuer = si.Issuer
	ci.SerialNumber = si.SerialNumber
	cert, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0, windows.CERT_FIND_SUBJECT_CERT, unsafe.Pointer(&ci), nil)
	runtime.KeepAlive(buf)
	if err != nil {
		return nil, fmt.Errorf("signer certificate not found: %v", err)
	}
	defer windows.CertFreeCertificateContext(cert)
	if cert.CertInfo == nil || cert.EncodedCert == nil || cert.Length == 0 {
		return nil, fmt.Errorf("empty signer certificate")
	}
	s := &authenticodeSigner{}
	if cert.CertInfo.Subject.Size > 0 && cert.CertInfo.Subject.Data != nil {
		s.subject = append([]byte(nil), unsafe.Slice(cert.CertInfo.Subject.Data, cert.CertInfo.Subject.Size)...)
	}
	s.thumbprint = sha1.Sum(unsafe.Slice(cert.EncodedCert, cert.Length))
	if n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, nil, 0); n > 1 {
		nb := make([]uint16, n)
		windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &nb[0], n)
		s.name = windows.UTF16ToString(nb)
	}
	return s, nil
}
