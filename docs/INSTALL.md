# Installing Farrier

What you get from this is a fleet that reports: inventory, systemd unit state, pending updates with
security separated from the rest, and which services still hold replaced libraries.

The privileged operations are real now — applying updates, starting, stopping and restarting a unit,
rebooting — and each is bounded by a root-owned file the control plane cannot modify. The control plane
can ask for them: `POST /api/v1/jobs` queues one, and whether it then waits for somebody to release it
is a setting on your fleet — see [`SECURITY.md` §3](SECURITY.md#3-the-intent-catalogue).

**What is missing is `farrier sign`.** A destructive job carries a signature made offline by a key the
control plane does not hold, and nothing yet produces one for a human — so until it lands, the API
drives read-only work and a privileged operation is something an administrator runs on a host, through
the same helpers and the same policy check the agent would have gone through.

## The control plane

You need PostgreSQL 14 or newer, and one binary.

```bash
# 1. The certificate authority that issues agent certificates.
sudo farrier-server ca init --ca-dir /var/lib/farrier-server/ca

# 2. A database. An ordinary role that owns the schema — not the postgres superuser.
sudo -u postgres createuser farrier --pwprompt
sudo -u postgres createdb --owner farrier farrier

# 3. Run it. The schema is created on first start.
export FARRIER_DATABASE_URL='postgres://farrier:...@localhost/farrier?sslmode=disable'
export FARRIER_ADMIN_TOKEN="$(openssl rand -hex 32)"
farrier-server serve --addr :8443 --ca-dir /var/lib/farrier-server/ca
```

**Connect as an ordinary role, not as `postgres`.** Fleets are isolated from one another by PostgreSQL
row-level security, and a superuser — or any role with `BYPASSRLS` — is exempt from every policy in the
schema. The exemption has no symptom whatsoever: the policies are still there, the queries still carry
their predicates, and every query returns every fleet's rows. `farrier-server` checks its own role at
startup and refuses to run on either, so you will be told rather than left to find out. See
[`SECURITY.md` §5](SECURITY.md#5-tenants).

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

### More than one fleet

The command above gives you a fleet called `default`, and if that is all you want you can stop reading
this section — everything below is optional and nothing above changes.

One control plane can serve several independent fleets. They share the binary, the database and the
certificate authority, and they share nothing else: no fleet can see another's hosts, tokens, jobs or
results, and an operator credential reaches exactly one of them. There is no fleet in any URL, so there
is nothing an operator could edit to be somewhere else.

Provisioning one is a separate credential's job:

```bash
export FARRIER_PLATFORM_TOKEN="$(openssl rand -hex 32)"
farrier-server serve --addr :8443 --ca-dir /var/lib/farrier-server/ca

curl -sX POST https://control.example.org/api/v1/tenants \
  -H "Authorization: Bearer $FARRIER_PLATFORM_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"slug":"acme","displayName":"Acme Ltd","approvalMode":"second_person"}'
```

The platform token administers fleets and **reaches no fleet's hosts or jobs** — every operator route
refuses it, and every fleet route refuses an operator credential. That separation is the point of
having two tokens rather than one: running Farrier for other people should not require being able to
read what they run.

It also cannot issue a fleet's operator credential. That belongs to whatever authenticates your
operators — `auth.Provider` is the seam, and the shipped token provider binds one token to one fleet
with `--tenant`:

```bash
farrier-server serve --tenant acme --admin-token "$ACME_TOKEN" ...
```

`approvalMode` is that fleet's answer to "who has to agree before a host may act on a destructive job",
and it is per fleet because a one-person shop and a regulated customer cannot share an answer. The three
values and the reasoning are in [`SECURITY.md` §3](SECURITY.md#3-the-intent-catalogue).

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

## Asking a host to do something

```bash
# Read-only work needs nothing but an operator credential.
curl -sX POST https://farrier.example.org/api/v1/jobs \
  -H "Authorization: Bearer $FARRIER_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"hostId":"01J…","intent":"facts.collect","params":{}}'

curl -s "https://farrier.example.org/api/v1/jobs?host=01J…" \
  -H "Authorization: Bearer $FARRIER_ADMIN_TOKEN"
```

A job comes back with a `state`: `queued`, `awaiting_approval`, `running`, or whatever status the host
reported. The `result` is null until the host reports one, which is how "not reported yet" stays
distinguishable from "reported nothing".

A **destructive** job — applying every update, starting, stopping or restarting a unit, rebooting —
needs two more things, and neither of them is the control plane's to give.

1. A signature over the job, made offline with a key listed in that host's own
   `/etc/farrier/trusted-signers`. It is sent with the request, along with the `id`, `nonce`,
   `notBefore` and `notAfter` it covers; every one of those comes from the signer, because a value
   chosen by the control plane would invalidate the signature. **`farrier sign` is not written yet**,
   so there is no supported way for a person to produce one today.
2. Approval by a *different* operator, through `POST /api/v1/jobs/{id}/approve`. Until that happens no
   host can claim the job. A control plane with one operator account cannot do this at all — see
   [`SECURITY.md`](SECURITY.md#destructive--signed-by-a-key-in-the-hosts-trusted-signers).

A **routine** job — `packages.applySecurity` — is refused outright, and the refusal says why: it is the
one tier that carries no offline signature, so an agent must verify a signature by the control plane's
online key instead, and there is no online key yet.

## What a fresh host will and will not do

Straight after installation, before you change anything:

| | |
| --- | --- |
| Reports inventory, services, pending updates and reboot state | **yes** |
| Applies security updates on its own timer, via `unattended-upgrades` | **yes** — and it keeps doing this if the control plane is unreachable, or if you never enrol it at all |
| Applies updates because the control plane asked | **no** — `packages.applySecurity` has no executor, and `packages.applyAll` needs a signature from a key you place on the host |
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
