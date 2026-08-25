# A cloud-init baseline

[`wheel-and-unattended-upgrades.yaml`](wheel-and-unattended-upgrades.yaml) is one worked template body:
unattended security updates left on, a `wheel` group, `su` restricted to that group, and one
administrator in it. It is an example and not a default. Farrier ships no template — what a machine
should look like on its first boot is a decision about a fleet, and a project that shipped one would be
making it for you.

It is here because a template body is the one document in Farrier that an operator writes from scratch,
and because two of its details are easy to get wrong in ways that produce a host which reports itself
patched and is not.

## What it does, and the parts worth reading

**Unattended upgrades stay the host's own business.** `20auto-upgrades` turns the periodic keys on;
`52unattended-upgrades-local` amends the distribution's `50unattended-upgrades` — 52 rather than 49,
because apt reads that directory in lexical order and a lower number is overridden by the file it means
to amend. It sets `--force-confdef`, `--force-confold` and `DPkg::Lock::Timeout`, which is what an
unattended run needs to not stop at a dpkg prompt no one will ever see, and it turns automatic reboots
off: whether this host may reboot is `/etc/farrier/policy.toml`'s answer, not the update mechanism's.

It deliberately does **not** set `Unattended-Upgrade::Origins-Pattern`. Debian and Ubuntu name their
security origins differently, each distribution's own file already has the right one, and a pattern
copied from the other distribution is exactly how a host stops applying security updates while still
reporting that unattended-upgrades is enabled. Farrier keeps a `Platform` seam in `internal/collect` for
the same four differences, for the same reason.

**`wheel` restricts `su`; it grants nothing.** The line added to `/etc/pam.d/su` is
`auth required pam_wheel.so use_uid group=wheel`, inserted immediately after `pam_rootok`, which is
`sufficient` and short-circuits — so root keeps its unauthenticated `su` and everybody else meets the
wheel check. The other reading of "allow `su` for the wheel group" is
`auth sufficient pam_wheel.so trust use_uid`, which lets a wheel member become root with **no password
at all**. That one is not in the example on purpose; if you want it, you are choosing it.

Nothing here adds `wheel` to sudoers either. `sudo` on Debian and Ubuntu is the `sudo` group and the
example leaves it alone, so an administrator's existing access does not change shape at first boot.

**It proves what it did.** The last four lines of the script assert the PAM edit, the group membership,
the periodic key that apt actually parses, and that the timer is enabled. A failure there fails the
`runcmd`, which is what makes `cloud-init status --long` report the boot as degraded — a baseline that
quietly did nothing is worse than one that failed loudly.

**A rendered value reaches a command as an argument.** `{{admin_user}}` is written into a file by
`write_files` and read back with `"$(cat …)"`, rather than being spliced into the `usermod` command
line. That is the same rule [`SECURITY.md` §7](../../docs/SECURITY.md#7-provisioning-and-the-enrolment-time-exception)
states for the agent — no byte of a template ever reaches a command line — applied inside a template to
the one value the template does not choose itself.

## Using it as a Tier 1 template

Farrier stores and renders this and never delivers it. The rendered `user-data` goes to whatever creates
the machine.

```bash
curl -sX POST https://farrier.example.org/api/v1/templates \
  -H "Authorization: Bearer $FARRIER_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg body "$(cat wheel-and-unattended-upgrades.yaml)" \
        '{name: "baseline", body: $body}')"

curl -sX POST https://farrier.example.org/api/v1/templates/baseline/render \
  -H "Authorization: Bearer $FARRIER_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"params":{"admin_user":"ubuntu"}}'
```

Every placeholder must be supplied: a render missing one is refused by name rather than emitting a
document with `{{admin_user}}` still in it. Treat the output as a credential once you add
`{{enrollmentToken}}` to the body — the render endpoint mints a real, single-use token into it, and
cloud-init `user-data` is plaintext in a metadata service and in `/var/lib/cloud/instance/user-data.txt`.

Adding enrolment is three more lines, and they are not in the example because they are the point at
which it stops being a baseline anybody can copy:

```yaml
runcmd:
  - [ farrier, enroll, --server, 'https://farrier.example.org', --token, '{{enrollmentToken}}' ]
```

## Using it as a Tier 2 bootstrap

`farrier enroll --bootstrap NAME` applies a named template once, on a host being enrolled by hand,
against a signature the control plane stores but cannot mint. Two things change:

1. **Replace `{{admin_user}}` with a literal name first.** A bootstrap body is applied as exactly the
   bytes that were signed, so a placeholder would reach the host as literal braces.
2. **Sign it, and establish the trust anchor before enrolling.** `--bootstrap` refuses on a host with an
   empty `trusted-signers` rather than falling back to trusting the server.

```bash
farrier sign-template --key ~/.config/farrier/ops.key --name baseline \
  --body ./baseline.yaml            # prints the whole body and asks before signing

sudo farrier enroll --server https://farrier.example.org --token frr_… \
     --signers ./trusted-signers --bootstrap baseline
```

## Checking it on the host

```bash
cloud-init status --long
apt-config dump APT::Periodic::Unattended-Upgrade
grep pam_wheel /etc/pam.d/su
id -nG ubuntu
```
