## What this changes, and why

<!--
The diff already shows what. This is the place for why: the problem, and why this is the shape of the
fix rather than another one. If it is a one-line fix for an obvious bug, one line here is plenty.
-->

## Checklist

- [ ] Every commit is signed off (`git commit -s`). There is no CLA; the DCO is what keeps the
      Apache-2.0 licence permanent.
- [ ] Everything is in English — identifiers, comments, commit messages, UI strings.
- [ ] Every new type and function has a doc comment saying what it does **and why it exists**.
      `make doccheck` checks that one exists; a reviewer checks that the "why" is real.
- [ ] `make lint` and `make test` pass.
- [ ] `make guarantee` passes.

## If this touches the agent, the helpers, the catalogue or the policy

- [ ] I have read [`docs/SECURITY.md`](../docs/SECURITY.md).
- [ ] This adds no way to get from a network message to a shell, an interpreter, or a program chosen at
      run time.
- [ ] Any new privileged operation is refusable by the host's own `policy.toml`, and the root helper
      re-checks it rather than trusting the agent.
- [ ] If this adds an intent, the expected-set literal in the guarantee test is updated in the same
      commit, and `docs/SECURITY.md` §3 and `docs/PROTOCOL.md` describe it.

<!--
Some things will be declined on principle rather than on their merits, and the reasons are written down
in advance so that nobody has to argue them each time: a shell.exec intent under any name, a plugin
loader in the agent, a fourth root helper, a database backend other than PostgreSQL, a server-to-agent
push channel, and weakening the signature requirement for "small" destructive operations. See
CONTRIBUTING.md and docs/EXTENDING.md. If there is a real operational problem behind one of these,
please open a discussion describing the problem rather than a pull request implementing the mechanism —
the usual outcome is a new typed intent, which is a normal reviewable change.
-->
