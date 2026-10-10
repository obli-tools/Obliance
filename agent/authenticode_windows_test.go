//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func requireFile(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); err != nil {
		t.Skipf("%s not present (build artifacts absent): %v", p, err)
	}
}

func orCode(err error) string {
	var oe *orError
	if errors.As(err, &oe) {
		return oe.Code
	}
	return ""
}

func TestAuthenticodeUnsignedRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "unsigned.msi")
	if err := os.WriteFile(p, []byte("definitely not a signed installer"), 0600); err != nil {
		t.Fatal(err)
	}
	err := verifySignerAgainst(p, nil, obliReachSignerPin, false)
	if orCode(err) != "signature_invalid" {
		t.Fatalf("unsigned file: %v", err)
	}
	if err := verifyObliReachSigner(p); orCode(err) != "signature_invalid" {
		t.Fatalf("production wrapper on an unsigned file: %v", err)
	}
}

func TestAuthenticodeDistMsiMatchesAgentSigner(t *testing.T) {
	exe := filepath.Join("dist", "obliance-agent.exe")
	msi := filepath.Join("dist", "oblireach-agent.msi")
	requireFile(t, exe)
	requireFile(t, msi)

	if err := winVerifyTrustFile(exe, false); err != nil && !isChainTrustError(err) {
		t.Skipf("reference agent exe is not validly signed here (%s)", trustErrorText(err))
	}
	ref, err := readAuthenticodeSigner(exe)
	if err != nil {
		t.Fatalf("read agent signer: %v", err)
	}
	t.Logf("agent signer: %q", ref.name)

	// Same subject as the agent's signer → accepted (with and without the
	// airgap cache-only URL retrieval).
	if err := verifySignerAgainst(msi, ref, "", false); err != nil {
		t.Fatalf("dist MSI vs agent signer: %v", err)
	}
	if err := verifySignerAgainst(msi, ref, "", true); err != nil {
		t.Fatalf("dist MSI vs agent signer (cache-only): %v", err)
	}
	// Pinned publisher alone (unsigned dev build of the agent) → accepted:
	// this also proves the pinned value matches the real certificate. The pin
	// is only set by the release build (-ldflags -X).
	if obliReachSignerPin != "" {
		if err := verifySignerAgainst(msi, nil, obliReachSignerPin, false); err != nil {
			t.Fatalf("dist MSI vs pinned publisher %q: %v", obliReachSignerPin, err)
		}
	}
	// Neither the reference subject nor the pin → refused.
	if err := verifySignerAgainst(msi, nil, "Someone Else", false); orCode(err) != "signer_mismatch" {
		t.Fatalf("foreign pin: %v", err)
	}
	other := &authenticodeSigner{subject: []byte("CN=Other"), name: "Other"}
	if err := verifySignerAgainst(msi, other, "", false); orCode(err) != "signer_mismatch" {
		t.Fatalf("foreign reference: %v", err)
	}
}

func TestAuthenticodeTamperedMsiRefused(t *testing.T) {
	msi := filepath.Join("dist", "oblireach-agent.msi")
	requireFile(t, msi)
	data, err := os.ReadFile(msi)
	if err != nil {
		t.Fatal(err)
	}
	// Flip bytes in the middle of the payload (inside the embedded cab).
	for i := len(data) / 2; i < len(data)/2+16; i++ {
		data[i] ^= 0xFF
	}
	p := filepath.Join(t.TempDir(), "oblireach-agent.msi")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifySignerAgainst(p, nil, obliReachSignerPin, false); orCode(err) != "signature_invalid" {
		t.Fatalf("tampered MSI: %v", err)
	}
}
