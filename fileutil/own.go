// Package fileutil reads and writes files that another user must not be
// able to steer: state a process acts on, a root service among them.
package fileutil

import (
	"errors"
	"io"
	"os"
)

// ErrNotOwn is ReadOwnFile's refusal: the file is not a regular file, is
// another user's, or is writable by its group or by everyone.
var ErrNotOwn = errors.New("not this user's own file")

// ErrNotPrivate is ReadPrivateFile's refusal: the file is not a regular
// file, is another user's, or its group or everyone can read or write it.
var ErrNotPrivate = errors.New("not this user's private file")

// ReadOwnFile reads path when only this process's user can have written it:
// a regular file it owns, not writable by its group or by everyone. A file
// another user planted is refused with ErrNotOwn.
func ReadOwnFile(path string) ([]byte, error) { return readOwn(path, os.Geteuid(), 0o022, ErrNotOwn) }

// ReadPrivateFile reads path when it holds this process's user's secret
// (a private key): a regular file it owns that no one else can read or
// write, mode 0600 or narrower. Anything else is refused with
// ErrNotPrivate.
func ReadPrivateFile(path string) ([]byte, error) { return ReadPrivateFileOf(path, os.Geteuid()) }

// ReadPrivateFileOf is ReadPrivateFile as user uid would answer it, asked
// by another user: root setting up a service that runs as uid, and
// checking the secret the service will read.
func ReadPrivateFileOf(path string, uid int) ([]byte, error) {
	return readOwn(path, uid, 0o077, ErrNotPrivate)
}

// readOwn reads path when it is a regular file of user uid with none of
// the deny permission bits, checked on the file it opened (no
// check-then-open race), else refuses with refusal.
func readOwn(path string, uid int, deny os.FileMode, refusal error) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || !ownFile(fi, uid, deny) {
		return nil, refusal
	}
	return io.ReadAll(f)
}
