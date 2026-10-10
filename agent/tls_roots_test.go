package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestFallbackRootsPEM: the embedded set is exactly the documented roots.
func TestFallbackRootsPEM(t *testing.T) {
	want := map[string]string{
		"ISRG Root X1":                          "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
		"ISRG Root X2":                          "69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470",
		"DigiCert Global Root G2":               "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f",
		"USERTrust RSA Certification Authority": "e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2",
		"USERTrust ECC Certification Authority": "4ff460d54b9c86dabfbcfc5712e0400d2bed3fbc4d4fbdaa86e06adcd2a9ad7a",
		"GTS Root R1":                           "d947432abde7b7fa90fc2e6b59101b1280e0e1c7e4e40fa3c6887fff57a7f4cf",
		"GTS Root R4":                           "349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d",
	}
	rest := fallbackRootsPEM
	got := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(c.Raw)
		if fp, ok := want[c.Subject.CommonName]; !ok || fp != hex.EncodeToString(sum[:]) {
			t.Errorf("unexpected root %q %x", c.Subject.CommonName, sum)
		}
		if !c.IsCA || c.NotAfter.Before(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("root %q: CA=%v notAfter=%s", c.Subject.CommonName, c.IsCA, c.NotAfter)
		}
		got++
	}
	if got != len(want) {
		t.Errorf("%d roots, want %d", got, len(want))
	}
	if fallbackRoots() == nil {
		t.Fatal("pool")
	}
}

type testPKI struct {
	root, inter, leaf *x509.Certificate
	leafKey           *ecdsa.PrivateKey
}

func newTestPKI(t *testing.T, host string, leafNotAfter time.Time) testPKI {
	t.Helper()
	mk := func(tmpl, parent *x509.Certificate, pub, signer interface{}) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root := mk(rootT, rootT, &rootKey.PublicKey, rootKey)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Inter"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	inter := mk(interT, root, &interKey.PublicKey, rootKey)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: host}, NotBefore: now.Add(-time.Hour), NotAfter: leafNotAfter,
		DNSNames: []string{host}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leaf := mk(leafT, inter, &leafKey.PublicKey, interKey)
	return testPKI{root: root, inter: inter, leaf: leaf, leafKey: leafKey}
}

func TestVerifyServerChainFallback(t *testing.T) {
	p := newTestPKI(t, "obliance.example", time.Now().Add(time.Hour))
	cs := tls.ConnectionState{ServerName: "obliance.example", PeerCertificates: []*x509.Certificate{p.leaf, p.inter}}
	system := x509.NewCertPool() // "Windows store" without the root
	fallback := x509.NewCertPool()
	fallback.AddCert(p.root)

	var ua x509.UnknownAuthorityError
	if err := verifyServerChain(cs, system, nil); !errors.As(err, &ua) {
		t.Fatalf("no fallback: want unknown authority, got %v", err)
	}
	if err := verifyServerChain(cs, system, fallback); err != nil {
		t.Fatalf("fallback should validate: %v", err)
	}
	// The fallback never excuses another error: wrong host name.
	bad := cs
	bad.ServerName = "evil.example"
	if err := verifyServerChain(bad, system, fallback); err == nil {
		t.Fatal("host name mismatch accepted")
	}
	// Missing intermediate: the fallback holds roots only.
	noInter := cs
	noInter.PeerCertificates = []*x509.Certificate{p.leaf}
	if err := verifyServerChain(noInter, system, fallback); err == nil {
		t.Fatal("chain without intermediate accepted")
	}
	// Unrelated fallback roots do not help.
	if err := verifyServerChain(cs, system, fallbackRoots()); !errors.As(err, &ua) {
		t.Fatalf("embedded roots must not validate a test CA: %v", err)
	}
	if err := verifyServerChain(tls.ConnectionState{}, system, fallback); err == nil {
		t.Fatal("no certificate accepted")
	}

	expired := newTestPKI(t, "obliance.example", time.Now().Add(-time.Minute))
	fb2 := x509.NewCertPool()
	fb2.AddCert(expired.root)
	csExp := tls.ConnectionState{ServerName: "obliance.example", PeerCertificates: []*x509.Certificate{expired.leaf, expired.inter}}
	if err := verifyServerChain(csExp, x509.NewCertPool(), fb2); err == nil || errors.As(err, &ua) {
		t.Fatalf("expired leaf must fail with an expiry error, got %v", err)
	}
}

// End to end through crypto/tls + net/http with the same VerifyConnection
// wiring as fallbackTLSConfig, "system" store lacking the root.
func TestFallbackTLSHandshake(t *testing.T) {
	p := newTestPKI(t, "obliance.example", time.Now().Add(time.Hour))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{p.leaf.Raw, p.inter.Raw}, PrivateKey: p.leafKey}}}
	srv.StartTLS()
	defer srv.Close()

	fallback := x509.NewCertPool()
	fallback.AddCert(p.root)
	client := func(fb *x509.CertPool) *http.Client {
		return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			ServerName:         "obliance.example",
			InsecureSkipVerify: true,
			VerifyConnection:   func(cs tls.ConnectionState) error { return verifyServerChain(cs, x509.NewCertPool(), fb) },
		}}}
	}
	resp, err := client(fallback).Get(srv.URL)
	if err != nil {
		t.Fatalf("with fallback: %v", err)
	}
	resp.Body.Close()
	if _, err := client(nil).Get(srv.URL); err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("without fallback: want unknown authority, got %v", err)
	}
	if cfg := fallbackTLSConfig(); !cfg.InsecureSkipVerify || cfg.VerifyConnection == nil {
		t.Fatal("fallbackTLSConfig wiring")
	}
}
