package intent

// Refused enumerates operation names this project has permanently declined to implement.
//
// It exists in code, and not only in docs/SECURITY.md, so that the refusal is enforced rather than
// merely stated: the guarantee suite asserts that no member of this list is in the catalogue and that
// no catalogue member's name is shaped like one. A future maintainer who adds "shell.exec" therefore
// gets a failing required check rather than a passing test run and a difficult conversation later.
//
// The reason for each is written down in docs/SECURITY.md under "Permanently refused". In an
// open-source project the request arrives eventually, usually from someone with a real problem, and
// the answer needs to be a document rather than an argument.
var Refused = []Name{
	"shell.exec",
	"script.run",
	"file.write",
	"apt.addRepository",
	"user.create",
	"ssh.authorizedKeys.add",
	"agent.updateFromURL",
}

// executionShapedFragments are substrings that must never appear in a catalogue member's name.
//
// This is a deliberately blunt instrument aimed at a specific failure: not a maintainer who decides to
// add remote execution, but one who adds something adjacent to it under a name that reads as harmless
// in a diff. Matching on the name catches "packages.execHook" and "facts.collectScript" without
// anyone having to notice what they do.
//
// A legitimate future intent that trips this list can be renamed, and being made to rename it is the
// check doing its job: an operation whose natural name contains "exec" is worth arguing about in a
// pull request.
var executionShapedFragments = []string{
	"exec",
	"shell",
	"script",
	"command",
	"cmd",
	"eval",
	"spawn",
	"system",
	"bash",
	"powershell",
	"invoke",
	"plugin",
	"download",
	"upload",
	"fetch",
	"url",
	"chroot",
	"sudo",
	"setuid",
	"authorizedkeys",
	"addrepo",
	"writefile",
	"filewrite",
}
