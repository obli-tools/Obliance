//go:build !windows

package main

// verifyObliReachSigner: no Authenticode outside Windows. The ObliReach
// binary is verified by the mandatory SHA-256 + size that come over the
// authenticated /api/agent/push exchange (see verifyObliReachArtifact).
func verifyObliReachSigner(path string) error { return nil }
