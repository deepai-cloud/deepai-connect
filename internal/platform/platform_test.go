package platform

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

func testDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRuntimeLockIsScopedToConnect(t *testing.T) {
	config := testDir(t)
	t.Setenv("HOME", config)
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv("AppData", config)
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	parentUnlock, err := Lock(filepath.Join(config, "deepai", ".runtime"))
	if err != nil {
		t.Fatal(err)
	}
	defer parentUnlock()
	dir, err := DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := Lock(filepath.Join(dir, ".runtime"))
	if err != nil {
		t.Fatalf("Connect runtime lock conflicts with its parent: %v", err)
	}
	unlock()
}

func TestAtomicPrivateFile(t *testing.T) {
	dir := testDir(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credential")
	if err := WriteFile(path, []byte("old"), true); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("blocked"), true); !errors.Is(err, os.ErrExist) {
		t.Fatalf("exclusive write: %v", err)
	}
	if got, err := ReadFile(path); err != nil || string(got) != "old" {
		t.Fatalf("exclusive changed existing file: %q %v", got, err)
	}
	if err := WriteFile(path, []byte("new"), false); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadFile(path); err != nil || string(got) != "new" {
		t.Fatalf("replace: %q %v", got, err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("secret mode: %v", fi.Mode())
		}
		fi, _ = os.Stat(dir)
		if fi.Mode().Perm() != 0755 {
			t.Fatalf("existing directory permissions changed: %v", fi.Mode())
		}
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("temporary files leaked: %v %v", files, err)
	}
}

func TestSystemTempPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := WriteFile(path, []byte("secret"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(path); err != nil {
		t.Fatal(err)
	}
}

func TestExclusiveWriteRace(t *testing.T) {
	path := filepath.Join(testDir(t), "winner")
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if WriteFile(path, []byte("secret"), true) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d writes won; expected 1", wins.Load())
	}
}

func TestRejectSymlinksAndDirectories(t *testing.T) {
	dir := testDir(t)
	real := filepath.Join(dir, "real")
	if err := WriteFile(real, []byte("original"), true); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := WriteFile(link, []byte("bad"), false); err == nil {
		t.Fatal("wrote through symlink")
	}
	if _, err := ReadFile(link); err == nil {
		t.Fatal("read through symlink")
	}
	if got, _ := os.ReadFile(real); string(got) != "original" {
		t.Fatal("symlink target changed")
	}
	linkedDir := filepath.Join(dir, "directory-link")
	if err := os.Symlink(dir, linkedDir); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(filepath.Join(linkedDir, "new"), []byte("bad"), true); err == nil {
		t.Fatal("followed symlink parent")
	}
	if _, err := ReadFile(filepath.Join(linkedDir, "real")); err == nil {
		t.Fatal("read through symlink parent")
	}
	if _, err := Lock(linkedDir); err == nil {
		t.Fatal("locked through symlink parent")
	}
	if _, err := ReadFile(dir); err == nil {
		t.Fatal("read directory as credential")
	}
}

func TestLockContentionAndRelease(t *testing.T) {
	dir := testDir(t)
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if release, err := Lock(dir); err == nil {
		release()
		unlock()
		t.Fatal("second lock succeeded")
	}
	unlock()
	unlock, err = Lock(dir)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	unlock()
}
