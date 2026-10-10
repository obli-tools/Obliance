//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	// config.json (API key + server URL): root only.
	secretFileMode os.FileMode = 0o600
	// status.json: read by the unprivileged tray.
	publicFileMode os.FileMode = 0o644
)

// writeSecretFile writes a file only root can read (0600), atomically.
func writeSecretFile(path string, data []byte) error {
	return writeFileReplace(path, data, secretFileMode)
}

// writePublicFile writes a world-readable (0644) root-owned file, atomically.
func writePublicFile(path string, data []byte) error {
	return writeFileReplace(path, data, publicFileMode)
}

// writeFileReplace writes data to a temp file of the same directory (created
// 0600 by os.CreateTemp, so the secret is never world-readable, not even
// briefly), sets the final mode and renames it over path. The rename also
// drops whatever owner / mode / hard link the previous file had.
func writeFileReplace(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	fail := func(e error) error {
		f.Close()
		_ = os.Remove(tmp)
		return e
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	// Chmod (not the create mode) so the umask cannot widen or narrow it.
	if err := f.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// hardenSecretFile tightens an existing secret file in place to 0600 (used
// when it cannot be rewritten). Symlinks are refused, never followed.
func hardenSecretFile(path string) error {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Mode().Perm() == secretFileMode {
		return nil
	}
	return os.Chmod(path, secretFileMode)
}

// protectAgentRegistryKey: Windows only (the MSI's registry copy of the key).
func protectAgentRegistryKey() error { return nil }
