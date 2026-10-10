package main

// Fallback root CAs for Windows < 10.
//
// Windows 7 / Server 2008 R2 / 2012 machines whose automatic root update is
// disabled, blocked or offline lack ISRG Root X1 (Let's Encrypt) and other
// post-2015 roots in their certificate store: every HTTPS / WSS connection to
// the server then fails with x509 "certificate signed by unknown authority".
//
// On those systems ONLY (useFallbackRoots), the agent's TLS configs verify the
// server chain themselves (tls.Config.VerifyConnection): first exactly like
// Go's default (Roots nil = the Windows store through CertGetCertificateChain),
// and, ONLY when that fails with an unknown-authority error, a second time
// against the small embedded, documented root set of fallback_roots.pem.
// Verification is never disabled: chain signatures, validity dates, key
// usage and the host name are always checked, and any other error (expired,
// wrong host...) fails the handshake as before. InsecureSkipVerify is set
// only so the standard library hands verification to VerifyConnection.
//
// A machine configured with tlsInsecureSkipVerify keeps that behaviour
// (tls_config.go); Windows 10+ and other OSes are untouched.

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"log"
	"sync"
)

//go:embed fallback_roots.pem
var fallbackRootsPEM []byte

var (
	fallbackRootsOnce sync.Once
	fallbackRootsPool *x509.CertPool
	fallbackUsedOnce  sync.Once
)

// fallbackRoots parses the embedded roots once.
func fallbackRoots() *x509.CertPool {
	fallbackRootsOnce.Do(func() {
		p := x509.NewCertPool()
		if !p.AppendCertsFromPEM(fallbackRootsPEM) {
			log.Printf("TLS: embedded fallback roots could not be parsed")
		}
		fallbackRootsPool = p
	})
	return fallbackRootsPool
}

// verifyServerChain verifies cs like crypto/tls does by default (systemRoots
// nil = the platform verifier), then retries with fallback, if not nil, when
// the only problem is an unknown authority. The original error is returned
// when the fallback does not validate the chain either.
func verifyServerChain(cs tls.ConnectionState, systemRoots, fallback *x509.CertPool) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("tls: server sent no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{
		DNSName:       cs.ServerName,
		Intermediates: inter,
		Roots:         systemRoots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	_, err := cs.PeerCertificates[0].Verify(opts)
	if err == nil || fallback == nil {
		return err
	}
	var ua x509.UnknownAuthorityError
	if !errors.As(err, &ua) {
		return err
	}
	opts.Roots = fallback
	if _, err2 := cs.PeerCertificates[0].Verify(opts); err2 != nil {
		return err
	}
	fallbackUsedOnce.Do(func() {
		log.Printf("TLS: %s validated with the embedded fallback root CAs (the Windows root store lacks the issuing root: install the root certificate updates)", cs.ServerName)
	})
	return nil
}

// fallbackTLSConfig returns a client config that verifies through
// verifyServerChain with the embedded roots as fallback.
func fallbackTLSConfig() *tls.Config {
	roots := fallbackRoots()
	return &tls.Config{
		InsecureSkipVerify: true, // verification is done by VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyServerChain(cs, nil, roots)
		},
	}
}

// useFallbackRoots: Windows < 10 (NT 6.x) only.
func useFallbackRoots() bool { return osNeedsNT6Build() }

// serverTLSConfig is the config wsConnect uses when its caller passes none:
// the fallback-aware config on Windows < 10, a plain default elsewhere.
func serverTLSConfig() *tls.Config {
	if useFallbackRoots() {
		return fallbackTLSConfig()
	}
	return &tls.Config{}
}
