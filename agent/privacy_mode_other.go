//go:build !darwin

package main

import "os"

// privacyFileMode: 0666 so the Linux tray (running as the logged-in user)
// can toggle privacy.json; on Windows the mode only maps to the read-only
// attribute and NTFS ACLs (ensureUsersWritable) govern access.
const privacyFileMode os.FileMode = 0666

// hardenPrivacyFile is a no-op outside macOS.
func hardenPrivacyFile() {}
