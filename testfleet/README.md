# Test fleet

Five real machines — Ubuntu 22.04, 24.04 and 26.04, Debian 12 and 13 — running the real `.deb`, driven
by LXD.

It exists because the failures Farrier most needs to avoid do not reproduce against mocks. A conffile
prompt that hangs, a reboot marker that is an Ubuntu convention rather than a standard, a package
upgrade that quietly replaces a trust anchor, a job result lost because the machine went away before it
was sent: every one of those is a property of a real machine running a real package manager, and a test
double would confirm whatever its author believed rather than what dpkg does.

```bash
./fleet.sh up            # launch and install
./fleet.sh test          # every scenario on every release
./fleet.sh test 040-upgrade
./fleet.sh shell ubuntu/24.04
./fleet.sh down
./fleet.sh ci            # up, test, down — what the integration workflow runs
```

Needs LXD: `sudo snap install lxd && sudo lxd init --auto`.

| Variable | |
| --- | --- |
| `FARRIER_RELEASES` | Which releases to cover, space-separated. Defaults to all five |
| `FARRIER_VM=0` | Use system containers instead of virtual machines. Faster, and the reboot scenarios then test rather less than they claim to, so they skip |

## The scenarios

| | |
| --- | --- |
| `010-install` | The package installs, the account cannot log in and is not in the `docker` group, the conffiles are root-owned and unwritable by the agent, `trusted-signers` ships empty, and the helper refuses a restart the local policy does not permit |
| `020-hardening` | The hardening the unit file claims is actually in force, read back from systemd — which silently ignores directives it does not understand — and the agent can write its state and cannot write its policy |
| `030-facts` | The security/regular split, the reboot marker and Ubuntu Pro give the right answer *for this family*. All four of these differences fail quietly rather than loudly, so the answers are checked rather than the absence of an error |
| `040-upgrade` | A locally edited `policy.toml` and `trusted-signers` survive a package upgrade untouched. The second half is a **security** test: an upgrade that reset the trust anchor would re-open every destructive operation an administrator had closed |
| `050-conffile-prompt` | An update run with a changed conffile completes rather than hanging. `DEBIAN_FRONTEND=noninteractive` alone is not enough, and the run that hangs holds the apt lock until somebody notices days later |
| `060-kill-switch` | `/etc/farrier/paused` and `systemctl stop` both stop the host acting, the agent cannot remove the marker itself, and nothing flips it back on |
| `070-reboot-result` | A job result fsynced to the spool survives a **hard** reset and is still there afterwards. A result that only survives an orderly shutdown is not surviving anything |
| `080-write-capability` | The installed package refuses every privileged operation for want of an executor, under a policy that permits everything — so the refusal cannot be the policy's doing. There are exactly three root helpers and none of them accepts a program to run |

## What is pending

Phase 0 ships no write capability, so some scenarios currently assert the *invariant a phase 1 executor
must satisfy* rather than driving the executor itself. `050-conffile-prompt` demonstrates the dpkg
options against real dpkg on the machine; `070-reboot-result` exercises the durability mechanism
directly. Both are written now so that they fail the moment an executor lands without them, which is the
point at which somebody would otherwise have to remember.

`080-write-capability` is expected to *stop passing* when phase 1 begins. That failure is the
notification, and updating it should be a deliberate, visible line in the diff rather than something
that happens quietly.

## Why shell

The harness drives real machines over LXD, which is an inherently shell-shaped job, and it may use a
shell freely — `internal/intent`'s source-level check that no shipped code reaches a shell deliberately
excludes this directory. Holding a test harness to that rule would only teach people to add exemptions.
