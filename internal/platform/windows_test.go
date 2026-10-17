//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestProtectFileUsesOpenHandle(t *testing.T) {
	dir := testDir(t)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, err := root.OpenFile("credential", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Keep the same handle while invalidating its original pathname. Securing
	// credentials must operate on the opened object, without another path lookup.
	if err := root.Rename("credential", "renamed"); err != nil {
		t.Fatal(err)
	}
	if err := protectFile(f); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("secret"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "renamed")
	if data, err := os.ReadFile(path); err != nil || string(data) != "secret" {
		t.Fatalf("protected handle no longer writes its file: %q, %v", data, err)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("credential still inherits permissions: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		t.Fatalf("credential must grant exactly the current user and LocalSystem access: %v", err)
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
			t.Fatalf("credential grants unexpected access: %s", sd.String())
		}
		want := windows.ACCESS_MASK(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE)
		if ace.Mask&want != want {
			t.Fatalf("credential does not grant its trusted principals read/write access: %s", sd.String())
		}
		seen[sid.String()] = true
	}
	if !seen[user.User.Sid.String()] || !seen[system.String()] {
		t.Fatalf("credential lost user or LocalSystem access: %s", sd.String())
	}
	runtime.KeepAlive(sd)
}
