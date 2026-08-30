//go:build !windows

package main

// The PKCS#11 backend, registered by its own init function.
//
// It is imported here rather than beside the others because it is the one backend that is not portable:
// it loads an operator-named module with dlopen, which purego provides on POSIX only. Windows has
// LoadLibrary and a Windows PKCS#11 module is an ordinary DLL, so this is a gap that could be closed —
// it is not closed here because doing it properly means a second FFI path through the file the guarantee
// suite already treats as special, and that is its own change with its own review.
//
// What a Windows operator loses is the ability to sign with a token from this machine. `file` and `kms`
// both work there, and a Windows *host* needs none of them: it executes only the read tier, which
// requires no signature at all. See backend_windows.go, which says so to whoever types a pkcs11:
// reference.
import _ "github.com/pascalgross/farrier/internal/signing/backend/pkcs11"
