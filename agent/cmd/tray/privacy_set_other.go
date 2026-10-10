//go:build !darwin

package main

// setPrivacy writes privacy.json directly: the daemon watches the file
// (Windows: NTFS ACL grants Users modify on this file only; Linux: 0666).
func setPrivacy(enabled bool) error {
	return writePrivacyFile(enabled, "user")
}
