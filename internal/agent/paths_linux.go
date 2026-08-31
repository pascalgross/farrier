//go:build linux

package agent

// DefaultStateDir is where the agent keeps everything it writes.
//
// It is the only writable path the hardened systemd unit grants, which is deliberate: an agent that can
// write nowhere else cannot be talked into leaving something behind in a directory that matters.
const DefaultStateDir = "/var/lib/farrier"

// DefaultServerCABundle is where an administrator puts the control plane's CA before enrolling.
//
// It exists because enrolment is the one request an agent makes with nothing on disk to verify against.
// Every request after it uses the bundle the enrolment response carried, written to CABundleFile — but
// that response is itself fetched over TLS, so the first connection needs an authority chosen locally
// and in advance. `farrier enroll` reads this path when --ca is not given, which is what makes the
// documented ordering — install the certificate, then enrol — mean something rather than being a step
// that writes a file nothing opens.
//
// /etc/farrier rather than the state directory: this is administrator-supplied configuration, chosen
// before the agent exists, and the state directory is the agent's to rewrite.
const DefaultServerCABundle = "/etc/farrier/server-ca.crt"

// MachineIDPath is systemd's machine identifier, which is documented as confidential.
const MachineIDPath = "/etc/machine-id"
