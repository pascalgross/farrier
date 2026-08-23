# Installing Farrier

What you get from this is a fleet that reports: inventory, systemd unit state, pending updates with
security separated from the rest, and which services still hold replaced libraries.

The privileged operations are real now — applying updates, starting, stopping and restarting a unit,
rebooting — and each is bounded by a root-owned file the control plane cannot modify. But **the control
plane cannot yet ask for one**: there is no job-creation API and no `farrier sign`, so nothing reaches a
host from the server side. Until that lands, a privileged operation is something an administrator runs
on a host, through the same helpers and the same policy check the agent would have gone through.

## The control plane

You need PostgreSQL 14 or newer, and one binary.

```bash
# 1. The certificate authority that issues agent certificates.
sudo farrier-server ca init --ca-dir /var/lib/farrier-server/ca

# 2. A database.
sudo -u postgres createuser farrier --pwprompt
sudo -u postgres createdb --owner farrier farrier

# 3. Run it. The schema is created on first start.
export FARRIER_DATABASE_URL='postgres://farrier:...@localhost/farrier?sslmode=disable'
export FARRIER_ADMIN_TOKEN="$(openssl rand -hex 32)"
farrier-server serve --addr :8443 --ca-dir /var/lib/farrier-server/ca
```

Two things about TLS are worth knowing before you reach them.

The agent protocol authenticates hosts with **client certificates**, which do not exist without TLS —
so a control plane with no certificate does not serve agents insecurely, it cannot serve them at all.
`farrier-server serve` therefore refuses to start without one, and issues one from its own CA if you do
not supply one. An enrolled agent trusts that automatically, because it is handed the CA bundle at
enrolment. A browser will not, so pass `--tls-cert` and `--tls-key` from whatever issues your public
certificates before operators use the interface in earnest.

Back up `ca.key` **separately from the database**. An attacker with both can impersonate hosts to this
control plane; an attacker with the database alone cannot. Neither lets them run code on a host: an
agent authorises a job by its class and its signature, not by who asked.

## A host

```bash
# On the control plane, or through the web interface:
curl -sX POST https://farrier.example.org/api/v1/tokens \
  -H "Authorization: Bearer $FARRIER_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"label":"web tier","group":"web-prod"}'
```

The token comes back once and is not recoverable: only its hash is stored, so a database dump does not
let its holder enrol hosts. It is single-use and expires in a day by default.

```bash
# On the host:
curl -fsSL https://farrier.tools/apt/farrier-archive-keyring.gpg \
  | sudo tee /usr/share/keyrings/farrier-archive-keyring.gpg > /dev/null
curl -fsSL https://farrier.tools/apt/farrier.sources \
  | sudo tee /etc/apt/sources.list.d/farrier.sources > /dev/null
sudo apt-get update && sudo apt-get install farrier-agent

sudo farrier enroll --server https://farrier.example.org --token frr_…
sudo systemctl restart farrier-agent
```

The `.sources` file uses deb822 with `Signed-By:` naming an explicit keyring, so the Farrier key is
trusted for the Farrier repository only. `apt-key` is never used: it installs a key that is trusted for
every repository on the system, which turns one compromised project into root on the machine.

## What a fresh host will and will not do

Straight after installation, before you change anything:

| | |
| --- | --- |
| Reports inventory, services, pending updates and reboot state | **yes** |
| Applies security updates on its own timer, via `unattended-upgrades` | **yes** — and it keeps doing this if the control plane is unreachable, or if you never enrol it at all |
| Applies updates because the control plane asked | **no** — the control plane cannot issue a job yet |
| Applies updates because an administrator ran the helper on the host | only security updates, and only what the policy below allows |
| Restarts a service, or reboots | **no**, from anyone, until you change the two files below |

The two files are the whole of it:

**`/etc/farrier/policy.toml`** — root-owned, a dpkg conffile, and the control plane cannot modify it.
It ships permitting security updates, no reboots, and no restartable units. Effective permission for
any job is `min(what the control plane asked for, what this file allows)` — never the maximum. Check an
edit with `farrier-agent policy check` before restarting anything: a file that does not parse makes the
host refuse all privileged work rather than fall back to a default, which is deliberate and is a
miserable way to discover a typo.

**`/etc/farrier/trusted-signers`** — root-owned, a dpkg conffile, and **empty**. Every destructive
operation needs a signature from a key listed here, and the control plane holds none of them. Generate
one on your own machine:

```bash
farrier key generate --out ~/.config/farrier/signing.key --id ops-laptop
# prints the line to paste into /etc/farrier/trusted-signers on the hosts that key may act on
```

A package upgrade never replaces either file. There is a test in `testfleet/` that asserts it, and for
`trusted-signers` that is a security test rather than a convenience one.

## Stopping a host

```bash
sudo touch /etc/farrier/paused      # refuse everything, immediately
sudo systemctl stop farrier-agent   # or just stop it
```

Neither can be undone by the control plane. There is deliberately no `agent.resume` operation: an off
switch that something else can flip back on is not an off switch. The host keeps patching from its
local policy either way — a paused host should not become an unpatched host.

## Upgrading the agent

Through APT, on the host's own schedule, like any other package. There is no `agent.updateFromURL` and
there never will be: a self-update from a control-plane-supplied URL replaces the binary that enforces
every other rule.

## Building from source

```bash
make build    # all binaries into ./dist
make web      # the Angular application, embedded into farrier-server
make deb      # the farrier-agent package
make test lint guarantee
```

Go 1.26 or newer. `make deb` needs [nfpm](https://nfpm.goreleaser.com/install/); `make web` needs Node
and pnpm.

## Where to look when something is wrong

```bash
journalctl -u farrier-agent -n 200     # the agent logs JSON; paste it whole rather than summarising
farrier-agent policy check             # most "it refused" reports are the policy working correctly
farrier-server catalogue               # everything the control plane can ask a host to do
```

The last one is worth running once even when nothing is wrong. It prints the complete, closed set of
operations plus the list this project has permanently refused to implement, and it is the fastest way
to check that the claim on the front page is true of the binary you actually installed.
