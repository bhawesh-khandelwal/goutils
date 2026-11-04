//go:build unix

package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReadOwnFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadOwnFile(path); err != nil || string(b) != "{}" {
		t.Fatalf("own file: %q, %v", b, err)
	}
	for _, m := range []os.FileMode{0o664, 0o666, 0o646} {
		if err := os.Chmod(path, m); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadOwnFile(path); !errors.Is(err, ErrNotOwn) {
			t.Errorf("mode %04o: %v, want ErrNotOwn", m, err)
		}
	}
	if _, err := ReadOwnFile(filepath.Dir(path)); !errors.Is(err, ErrNotOwn) {
		t.Errorf("directory: %v, want ErrNotOwn", err)
	}
	if os.Geteuid() == 0 {
		os.Chmod(path, 0o644)
		if err := os.Chown(path, 1000, 1000); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadOwnFile(path); !errors.Is(err, ErrNotOwn) {
			t.Errorf("uid 1000's file read by root: %v, want ErrNotOwn", err)
		}
	}
}

// A private file is the user's own and no one else's to read: 0600 or
// narrower.
func TestReadPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.key")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, m := range []os.FileMode{0o600, 0o400} {
		if err := os.Chmod(path, m); err != nil {
			t.Fatal(err)
		}
		if b, err := ReadPrivateFile(path); err != nil || string(b) != "secret" {
			t.Errorf("mode %04o: %q, %v", m, b, err)
		}
	}
	for _, m := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o606} {
		if err := os.Chmod(path, m); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadPrivateFile(path); !errors.Is(err, ErrNotPrivate) {
			t.Errorf("mode %04o: %v, want ErrNotPrivate", m, err)
		}
	}
	if _, err := ReadPrivateFile(filepath.Dir(path)); !errors.Is(err, ErrNotPrivate) {
		t.Errorf("directory: %v, want ErrNotPrivate", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFileOf(path, os.Geteuid()+1); !errors.Is(err, ErrNotPrivate) {
		t.Errorf("asked for another user: %v, want ErrNotPrivate", err)
	}
	if _, err := ReadPrivateFileOf(path, os.Geteuid()); err != nil {
		t.Errorf("asked for its owner: %v", err)
	}
	if _, err := ReadPrivateFile(path + ".missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v, want ErrNotExist", err)
	}
	if os.Geteuid() == 0 {
		os.Chmod(path, 0o600)
		if err := os.Chown(path, 1000, 1000); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadPrivateFile(path); !errors.Is(err, ErrNotPrivate) {
			t.Errorf("uid 1000's file read by root: %v, want ErrNotPrivate", err)
		}
	}
}

// A link at path is replaced, never written through, and the mode is the
// one asked for, not the old file's.
func TestWriteFileAtomicReplacesLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o666); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, strings.NewReader("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("wrote through the link: %q", b)
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
		t.Errorf("not a 0644 regular file: %v, %v", fi, err)
	}
}

// The owner is set before the file is in place; anyone may give a file to
// themselves, so this runs without root.
func TestWriteFileAtomicOwned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine")
	uid, gid := os.Getuid(), os.Getgid()
	if err := WriteFileAtomicOwned(path, strings.NewReader("x"), 0o755, uid, gid); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if int(st.Uid) != uid || int(st.Gid) != gid || fi.Mode().Perm() != 0o755 {
		t.Errorf("owner %d:%d mode %v", st.Uid, st.Gid, fi.Mode())
	}
}
