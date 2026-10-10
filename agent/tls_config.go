package main

import (
	"crypto/tls"
	"log"
	"net/http"
)

// applyTlsConfig honours cfg.TlsInsecureSkipVerify by cloning http.DefaultTransport
// with a permissive TLS config. This propagates the setting to every http.Client
// in the agent that uses the default transport (push, poller, downloads, etc.),
// matching the behaviour of the WebSocket command channel.
//
// When cfg.TlsInsecureSkipVerify is false (the default), this is a no-op and
// all TLS connections use the system trust store with full certificate
// verification.
//
// On Windows < 10 (verification ON), the default transport instead gets the
// fallback-root verifier of tls_roots.go (system store first, embedded roots
// only on an unknown-authority error).
func applyTlsConfig(cfg *Config) {
	if !cfg.TlsInsecureSkipVerify {
		if useFallbackRoots() {
			if base, ok := http.DefaultTransport.(*http.Transport); ok {
				t := base.Clone()
				t.TLSClientConfig = fallbackTLSConfig()
				http.DefaultTransport = t
				log.Printf("TLS: Windows < 10 — embedded fallback root CAs enabled for unknown-authority chains")
			}
		}
		return
	}
	log.Printf("[WARN] tlsInsecureSkipVerify=true — TLS certificate verification is DISABLED for all server connections")

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		http.DefaultTransport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		return
	}
	t := base.Clone()
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{}
	}
	t.TLSClientConfig.InsecureSkipVerify = true
	http.DefaultTransport = t
}
