//go:build windows

package desktop

import (
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsDesktopFilesHavePrivateACLs(t *testing.T) {
	cfg := desktopTestConfig(t)
	path, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := saveConfig(cfg); err != nil {
			t.Fatal(err)
		}
		assertPrivateWindowsFile(t, path)
	}
	path = filepath.Join(t.TempDir(), "kube", "config")
	if err := writeKubeconfigFile(path, []byte("first"), nil, false); err != nil {
		t.Fatal(err)
	}
	assertPrivateWindowsFile(t, path)
	assertPrivateWindowsFile(t, filepath.Dir(path))
	if err := writeKubeconfigFile(path, []byte("replacement"), []byte("first"), true); err != nil {
		t.Fatal(err)
	}
	assertPrivateWindowsFile(t, path)
}

// A POSIX 0600 mode does not protect credentials on Windows. Inspect the native
// DACL to ensure only this user and LocalSystem receive access after each write.
func assertPrivateWindowsFile(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("%s inherits access permissions: %v", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		t.Fatalf("%s must grant exactly the current user and LocalSystem access: %v", path, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || (!sid.Equals(user.User.Sid) && !sid.Equals(system)) {
			t.Fatalf("%s grants unexpected access: %s", path, sd.String())
		}
		want := windows.ACCESS_MASK(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE)
		if ace.Mask&want != want {
			t.Fatalf("%s does not grant its trusted principals read/write access: %s", path, sd.String())
		}
		seen[sid.String()] = true
	}
	if !seen[user.User.Sid.String()] || !seen[system.String()] {
		t.Fatalf("%s lost user or LocalSystem access: %s", path, sd.String())
	}
	runtime.KeepAlive(sd)
}
