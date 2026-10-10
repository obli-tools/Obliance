//go:build windows

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	// config.json: protected DACL (nothing inherited from ProgramData, whose
	// ACL grants BUILTIN\Users read), SYSTEM + Administrators full control
	// only. The tray reads status.json instead.
	secretFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	// HKLM\SOFTWARE\OblianceAgent (ServerUrl + ApiKey written by the MSI):
	// same rule. HKLM\SOFTWARE is readable by Users by default.
	agentRegistryKeyPath = `SOFTWARE\OblianceAgent`
	agentRegistrySDDL    = "D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)"
)

// writeSecretFile writes path so that only SYSTEM and Administrators can
// read it: a temp file is CREATED with the protected DACL (never readable by
// Users, not even briefly) and then renamed over path, which also replaces a
// file that a user planted beforehand (its owner could otherwise re-grant
// itself access). If the rename fails (target held open without
// FILE_SHARE_DELETE), the file is rewritten in place and protected
// explicitly.
func writeSecretFile(path string, data []byte) error {
	err := writeSecretFileReplace(path, data)
	if err == nil {
		return nil
	}
	if perr := protectSecretFile(path); perr != nil && !os.IsNotExist(perr) {
		return fmt.Errorf("%v; in-place protect: %v", err, perr)
	}
	if werr := os.WriteFile(path, data, 0600); werr != nil {
		return fmt.Errorf("%v; in-place write: %v", err, werr)
	}
	return protectSecretFile(path)
}

func writeSecretFileReplace(path string, data []byte) error {
	sd, err := windows.SecurityDescriptorFromString(secretFileSDDL)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	tmp := path + ".tmp-" + randomHex(6)
	p16, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	// CREATE_NEW: never reuse a file someone else created under that name.
	h, err := windows.CreateFile(p16, windows.GENERIC_WRITE, 0, sa,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// MoveFileEx(MOVEFILE_REPLACE_EXISTING): the moved file keeps its own
	// security descriptor.
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// protectSecretFile applies the protected SYSTEM + Administrators DACL to an
// existing file (drops inherited ACEs and any explicit BUILTIN\Users grant —
// older agents ran `icacls <dir> /grant Users:(M) /T`, which made config.json
// writable by every local user). It also tries to make Administrators the
// owner, so a user-owned file cannot be re-opened by its owner; that part is
// best effort (it needs an elevated / SYSTEM token).
func protectSecretFile(path string) error {
	if _, err := os.Lstat(path); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(secretFileSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if admins, aerr := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); aerr == nil {
		if windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			admins, nil, dacl, nil) == nil {
			return nil
		}
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

// hardenSecretFile: Windows flavour of the in-place fallback.
func hardenSecretFile(path string) error {
	err := protectSecretFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// writePublicFile writes a file readable by the tray (the inherited
// ProgramData ACL grants BUILTIN\Users read): temp file + rename, so a
// planted file is replaced by one owned by the agent.
func writePublicFile(path string, data []byte) error {
	tmp := path + ".tmp-" + randomHex(6)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return os.WriteFile(path, data, 0644)
	}
	return nil
}

// protectAgentRegistryKey applies the protected SYSTEM + Administrators DACL
// to HKLM\SOFTWARE\OblianceAgent (MSI copy of ServerUrl + ApiKey). The MSI
// sets the same DACL at install (PermissionEx in installer/*.wxs); this
// covers machines installed by older MSIs. No-op when the key is absent.
func protectAgentRegistryKey() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, agentRegistryKeyPath,
		windows.READ_CONTROL|windows.WRITE_DAC)
	if err == registry.ErrNotExist {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	sd, err := windows.SecurityDescriptorFromString(agentRegistrySDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(windows.Handle(k), windows.SE_REGISTRY_KEY,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
