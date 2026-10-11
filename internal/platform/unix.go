//go:build darwin || linux

package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

func checkEntry(path string, fi os.FileInfo) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		// macOS exposes its standard temp/config paths through root-owned aliases.
		if runtime.GOOS == "darwin" && (path == "/var" || path == "/tmp" || path == "/etc") && fi.Sys().(*syscall.Stat_t).Uid == 0 {
			if target, err := os.Readlink(path); err == nil && target == "private"+path {
				return nil
			}
		}
		return fmt.Errorf("refusing symlink: %s", path)
	}
	return nil
}

func protect(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errors.New("private directory belongs to another user")
	}
	return os.Chmod(path, 0700)
}

func protectFile(f *os.File) error { return f.Chmod(0600) }

func Lock(dir string) (func(), error) {
	if err := SecureDir(dir); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(dir, ".lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err == nil && (st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG) {
		err = errors.New("unsafe lock file")
	}
	if err == nil {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("Connect state is locked or inaccessible: %w", err)
	}
	return func() { unix.Flock(fd, unix.LOCK_UN); unix.Close(fd) }, nil
}
