package main

import (
	"encoding/json"
	"errors"
	"strings"
	"syscall"
	"testing"
)

func u64(v uint64) *uint64 { return &v }

func TestSHA2SigningSupported(t *testing.T) {
	if sha2SigningSupported(6, 1, nil) || !sha2SigningSupported(6, 1, []string{"KB3033929"}) {
		t.Error("6.1")
	}
	if !sha2SigningSupported(6, 2, nil) || !sha2SigningSupported(6, 3, nil) || !sha2SigningSupported(10, 0, nil) {
		t.Error("6.2+ native")
	}
}

func TestTLS12ClientEnabled(t *testing.T) {
	cases := []struct {
		maj, min    uint32
		en, dbd     *uint64
		want        bool
		description string
	}{
		{6, 1, nil, nil, false, "Win7 default"},
		{6, 1, u64(1), u64(0), true, "Win7 enabled per guidance"},
		{6, 1, u64(1), nil, true, "Win7 Enabled=1 only"},
		{6, 1, nil, u64(0), true, "Win7 DisabledByDefault=0 only"},
		{6, 1, u64(0), u64(0), false, "Win7 Enabled=0"},
		{6, 3, nil, nil, true, "8.1 default"},
		{6, 2, nil, u64(1), false, "2012 DisabledByDefault=1"},
		{6, 3, u64(0), nil, false, "2012 R2 Enabled=0"},
	}
	for _, c := range cases {
		if got := tls12ClientEnabled(c.maj, c.min, c.en, c.dbd); got != c.want {
			t.Errorf("%s: got %v", c.description, got)
		}
	}
}

func TestDotNet4VersionFromRelease(t *testing.T) {
	cases := map[uint64]string{533320: "4.8.1", 528049: "4.8", 461814: "4.7.2", 394806: "4.6.2", 379893: "4.5.2", 378389: "4.5", 1: "4.0"}
	for rel, want := range cases {
		if got := dotNet4VersionFromRelease(rel, true); got != want {
			t.Errorf("%d -> %q, want %q", rel, got, want)
		}
	}
	if dotNet4VersionFromRelease(0, false) != "" || dotNet4VersionFromRelease(0, true) != "4.0" {
		t.Error("no release")
	}
}

func TestSignatureFailureCode(t *testing.T) {
	bad := syscall.Errno(trustEBadDigest)
	noSig := syscall.Errno(trustENoSignature)
	other := syscall.Errno(0x80096019) // TRUST_E_BASIC_CONSTRAINTS
	if signatureFailureCode(bad, true, true) != "sha2_unsupported" {
		t.Error("bad digest, signed, KBs missing")
	}
	if signatureFailureCode(noSig, false, true) != "signature_invalid" {
		t.Error("unsigned file must stay signature_invalid")
	}
	if signatureFailureCode(bad, true, false) != "signature_invalid" {
		t.Error("KBs present: a bad digest is a bad file")
	}
	if signatureFailureCode(other, true, true) != "signature_invalid" {
		t.Error("unrelated error")
	}
	if isLikelySHA2SupportError(errors.New("x")) {
		t.Error("non-errno")
	}
	if !strings.Contains(sha2UnsupportedDetail, "KB4474419") {
		t.Error("detail")
	}
}

func TestNT6PrereqsJSONShape(t *testing.T) {
	sp1 := true
	b, _ := json.Marshal(NT6Prereqs{SP1: &sp1, SHA2Signing: true, SHA2KBs: []string{"KB4474419"}, KB2533623: true, TLS12Schannel: false, WMFVersion: "2.0", DotNet4x: "4.8"})
	want := `{"sp1":true,"sha2Signing":true,"sha2Kbs":["KB4474419"],"kb2533623":true,"tls12Schannel":false,"wmfVersion":"2.0","dotnet4x":"4.8"}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
	b, _ = json.Marshal(NT6Prereqs{})
	if string(b) != `{"sha2Signing":false,"kb2533623":false,"tls12Schannel":false,"dotnet4x":""}` {
		t.Fatalf("empty: %s", b)
	}
}

func TestWithPSTLS12Preamble(t *testing.T) {
	const body = "Invoke-WebRequest https://example.org\n"
	if got := withPSTLS12Preamble(body, 2); got != psTLS12Preamble+body {
		t.Errorf("PS2: %q", got)
	}
	if got := withPSTLS12Preamble(body, 4); !strings.HasPrefix(got, "try {") {
		t.Errorf("PS4: %q", got)
	}
	for _, v := range []int{0, 5, 7} {
		if withPSTLS12Preamble(body, v) != body {
			t.Errorf("PS%d must be untouched", v)
		}
	}
	for _, s := range []string{
		"param([string]$x)\n$x",
		"# comment\n\n<# help\n block #>\n#Requires -Version 2\nParam (\n $a\n)\n",
		"[CmdletBinding()]\nparam()\n",
		utf8BOM + "  PARAM(\n)",
	} {
		if withPSTLS12Preamble(s, 2) != s {
			t.Errorf("param block script modified: %q", s)
		}
	}
	for _, s := range []string{"$params = 1\n", "# param(x)\nWrite-Output 1", "<# unterminated"} {
		if withPSTLS12Preamble(s, 3) == s {
			t.Errorf("script without param block not prefixed: %q", s)
		}
	}
	if strings.Count(psTLS12Preamble, "\n") != 1 {
		t.Error("preamble must be one line")
	}
}
