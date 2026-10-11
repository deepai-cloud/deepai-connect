//go:build windows

package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func privateSD() (*windows.SECURITY_DESCRIPTOR, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString("O:" + u.User.Sid.String() + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + u.User.Sid.String() + ")")
}

func checkEntry(path string, fi os.FileInfo) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	a, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing reparse point: %s", path)
	}
	return nil
}

func protect(path string) error {
	sd, err := privateSD()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
}

func protectFile(f *os.File) error {
	sd, err := privateSD()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	// os.OpenFile does not request WRITE_DAC. Reopen the existing file handle
	// with that right, avoiding any second path lookup before securing it.
	h, _, callErr := windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile").Call(f.Fd(), windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, 0)
	if windows.Handle(h) == windows.InvalidHandle {
		return callErr
	}
	defer windows.CloseHandle(windows.Handle(h))
	return windows.SetSecurityInfo(windows.Handle(h), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func Lock(dir string) (func(), error) {
	if err := SecureDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, ".lock")
	if err := CheckPath(path); err != nil {
		return nil, err
	}
	sd, err := privateSD()
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, sa, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err == nil && (info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1) {
		err = errors.New("unsafe lock file")
	}
	overlap := &windows.Overlapped{}
	if err == nil {
		err = windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlap)
	}
	if err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("Connect state is locked or inaccessible: %w", err)
	}
	return func() { windows.UnlockFileEx(h, 0, 1, 0, overlap); windows.CloseHandle(h) }, nil
}
