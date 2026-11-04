//go:build !unix

package fileutil

import "os"

// ownFile is true where files have no numeric owner nor Unix permission
// bits (Windows): the state lives in the user's profile, whose ACL keeps
// other users out.
func ownFile(os.FileInfo, int, os.FileMode) bool { return true }
