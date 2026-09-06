# Documentation

| | |
| --- | --- |
| [`INSTALL.md`](INSTALL.md) | Getting a control plane and a host running, and what a fresh host will and will not do |
| [`SECURITY.md`](SECURITY.md) | The guarantee, the three mechanisms, the permanently refused operations, and an honest statement of what HostSeal does *not* defend against |
| [`PROTOCOL.md`](PROTOCOL.md) | The agent protocol, specified closely enough to reimplement |
| [`EXTENDING.md`](EXTENDING.md) | The seams that are open, and the ones that are closed on purpose |
| [`MAINTAINING.md`](MAINTAINING.md) | The repository settings, the release procedure and the archive signing key — everything that is a decision somebody makes once rather than a file |

## `PROPOSAL.md`

HostSeal's design document — the reasoning behind each decision, rather than the decision itself — lives
outside this repository and has not been copied in. Everything it settled that a reader of the code
needs is restated where the code is: `SECURITY.md` carries the guarantee and the refusals,
`EXTENDING.md` carries the seams and their limits, and the "why this exists" half of every doc comment
carries the rest.

That is deliberate rather than an oversight. A design document that travels with a codebase drifts from
it — the code changes in a pull request, the document changes when somebody remembers — and a reader
who finds a stale rationale trusts the current one less. Reasoning that matters is written next to the
thing it explains, where the same review that changes the code changes it.
