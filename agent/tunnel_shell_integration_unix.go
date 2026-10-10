//go:build !windows

package main

// tunnel_shell_integration_unix.go — the agent's bash rcfile
// (tunnel_shell_integration.go bashIntegration), written in its config folder
// and trusted only when nobody but root can change it: bash runs it as root
// for every remote terminal.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ensureBashIntegration returns the path of the agent's bash rcfile, written
// first when missing or different. An error: bash starts as a plain login
// shell (tunnel_shell_unix.go), as before.
func ensureBashIntegration() (string, error) {
	return ensureBashIntegrationIn(configDir, 0)
}

// ensureBashIntegrationIn does it in dir, for files owned by uid owner
// (root; tests: the current user). The folder must be owner's and writable
// by owner only; the file is replaced atomically (a new file, synced, then
// renamed over the old one: a link or a foreign file there is replaced, never
// followed), then checked again: a regular file of owner's, writable by owner
// only.
func ensureBashIntegrationIn(dir string, owner uint32) (string, error) {
	if err := checkRootOnly(dir, owner, true); err != nil {
		return "", err
	}
	path := filepath.Join(dir, bashIntegrationFile)
	want := []byte(bashIntegration)
	if checkRootOnly(path, owner, false) == nil {
		if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, want) {
			return path, nil
		}
	}
	tmp := filepath.Join(dir, "."+bashIntegrationFile+".tmp-"+randomHex(6))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("shell integration: %w", err)
	}
	_, werr := f.Write(want)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmp, 0o644)
	}
	if werr == nil {
		werr = os.Rename(tmp, path)
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("shell integration: %w", werr)
	}
	if err := checkRootOnly(path, owner, false); err != nil {
		return "", err
	}
	return path, nil
}

// checkRootOnly: path is (not through a link) a folder (dir) or a regular
// file, owned by owner, not writable by its group nor by others.
func checkRootOnly(path string, owner uint32, dir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("shell integration: %w", err)
	}
	if dir && !fi.IsDir() {
		return fmt.Errorf("shell integration: %s is not a folder", path)
	}
	if !dir && !fi.Mode().IsRegular() {
		return fmt.Errorf("shell integration: %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("shell integration: %s is writable by others", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("shell integration: no owner information")
	}
	if uint32(st.Uid) != owner {
		return fmt.Errorf("shell integration: %s is not owned by uid %d", path, owner)
	}
	return nil
}
