// Package platform provides private atomic storage and process locks.
package platform

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// SecureDir creates private storage. Existing ancestors are never chmodded.
func SecureDir(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if filepath.Dir(path) == path {
		return errors.New("refusing to use filesystem root as private storage")
	}
	if err = CheckPath(path); err != nil {
		return err
	}
	if err = os.MkdirAll(path, 0700); err != nil {
		return err
	}
	if err = CheckPath(path); err != nil {
		return err
	}
	return protect(path)
}

// Reject links (including Windows reparse points) before handling credentials.
func CheckPath(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		fi, err := os.Lstat(path)
		if err == nil {
			if err = checkEntry(path, fi); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

// WriteFile writes atomically inside a protected directory, without exposing a
// partly-written credential. Exclusive writes never overwrite an existing file.
func WriteFile(path string, data []byte, exclusive bool) error {
	dir, name := filepath.Dir(path), filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return errors.New("expected a file path")
	}
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err = SecureDir(dir); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := CheckPath(path); err != nil {
		return err
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer r.Close()
	tmp := "." + name + "." + rand.Text()
	f, err := r.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer r.Remove(tmp)
	if err = protectFile(f); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if exclusive {
		return r.Link(tmp, name)
	}
	return r.Rename(tmp, name)
}

// ReadFile rejects links and special files. OpenRoot confines traversal even if
// a path is concurrently changed, and the opened file is checked again.
func ReadFile(path string) ([]byte, error) {
	if err := CheckPath(path); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	fi, err := r.Lstat(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("credential must be a regular file")
	}
	f, err := r.Open(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("credential must be a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 16<<20+1))
	if len(b) > 16<<20 {
		return nil, errors.New("credential exceeds 16 MiB")
	}
	return b, err
}
