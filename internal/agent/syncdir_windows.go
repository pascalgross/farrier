//go:build windows

package agent

// SyncDir does nothing on Windows, because there is nothing it could do.
//
// The Linux implementation opens the directory and fsyncs it, which is what makes a rename durable
// across a power loss. Windows has no equivalent operation, and the obvious translation is not merely
// weaker — it fails. Go implements File.Sync as FlushFileBuffers, which Microsoft documents as
// requiring a handle opened for writing; os.Open gives a read-only one, and a directory cannot be
// opened for writing at all. So the faithful port returns ERROR_ACCESS_DENIED every time.
//
// That is why this is a no-op rather than a best effort. Returning the error would make **every**
// WriteFileAtomic report failure after its rename had already succeeded, and the consequences are worse
// than they sound: enrolment writes the credential through this path, so the agent would abort after
// the control plane had already consumed the single-use token — leaving a host that is registered,
// counted against the fleet, and permanently unable to authenticate. A durability guarantee that cannot
// be kept must not be turned into a failure that breaks the operation it was protecting.
//
// What is actually lost is narrower than "no durability". Every file is still written to a temporary
// file, fsynced with its own FlushFileBuffers — which does work, because that handle is open for
// writing — and then renamed with MoveFileEx, which is atomic on NTFS. So a crash never exposes a
// truncated file, and a reader never sees a half-written credential. What is not guaranteed is that the
// *directory entry* has reached the disk when this returns: a power loss in the window after the rename
// can leave the previous name in place. The file is intact either way, and the agent's recovery for
// both cases is the same — re-request the job, or re-enrol.
//
// docs/SECURITY.md §12.6 records this alongside the other things the Windows boundary does not check,
// because "results are fsynced before an operation that may not return" is a promise this project makes
// in writing, and it is one shade weaker here.
func SyncDir(string) error { return nil }
