# Installing Farrier

What you get from this is a fleet that reports: inventory, systemd unit state, pending updates with
security separated from the rest, and which services still hold replaced libraries.

The privileged operations are real now — applying updates, starting, stopping and restarting a unit,
rebooting — and each is bounded by a root-owned file the control plane cannot modify. The control plane
can ask for them: `POST /api/v1/jobs` queues one, and whether it then waits for somebody to release it
is a setting on your fleet — see [`SECURITY.md` §3](SECURITY.md#3-the-intent-catalogue).

A destructive job carries a signature made offline by a key the control plane does not hold. `farrier
sign` is what produces one, and it never contacts the server — it renders what you are about to
authorise from the same payload it then signs.

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

Back up `template.key` beside it, from the same directory, and treat it as part of the backup rather
than as part of the database. It encrypts provisioning template bodies at rest — which is why a database
dump is not a set of provisioning scripts — and a restore without it leaves every stored template
permanently unopenable. The control plane says exactly that when it happens, which is the difference
between an operator fixing their restore and filing a bug about templates being corrupt.

### In containers, if that is how you run things

The same two pieces — one binary and PostgreSQL — as a Compose stack, in
[`deploy/`](../deploy/README.md):

```bash
cd deploy
cp .env.example .env      # four passwords; `openssl rand -hex 32` for each
docker compose up -d
```

The first start builds the image from the checkout, creates the certificate authority, creates an
ordinary database role and the database it owns, and serves on `https://localhost:8443`. The role is
the part worth reading about before you deviate from it: the PostgreSQL image's own superuser is exempt
from every row-level security policy in the schema, which is the paragraph above with the failure mode
that has no symptom.

Traefik is optional, in an overlay of its own, and routes rather than terminates — a **TCP** router with
`tls.passthrough=true`. A proxy that terminated TLS would end the connection carrying an agent's client
certificate and open one that does not, and the only way for the server to keep identifying hosts across
that would be to believe a header that anything reaching the proxy's back end can set. What follows from
passthrough — which certificate a browser sees, and why enrolling a rack at once through a proxy meets
the rate limiter — is in [`deploy/README.md`](../deploy/README.md).

A certificate a browser trusts comes from giving the interface a **second** hostname, where Traefik does
terminate and Let's Encrypt applies normally. Agents keep the passthrough name and need no public
certificate at all, because they verify against the CA bundle they were handed at enrolment. That is a
second overlay, and the agent endpoints are refused on the interface name.

A streaming replica is a second overlay. The database is configured for one from its first start, so
adding it later needs no restart of a primary that is by then serving a fleet.

### Mail, for alerts that reach somebody who is not looking

Optional, and off until you configure it. Alerting rules are per fleet and editable in the interface;
which relay this installation may speak to is yours:

```bash
farrier-server serve \
  --smtp-host smtp.example.com --smtp-port 587 \
  --smtp-from farrier@example.com --smtp-username farrier \
  --smtp-password-file /etc/farrier-server/smtp.password \
  ...
```

Port 465 speaks TLS from the first byte and anything else — 587 in practice — upgrades with STARTTLS.
Plaintext SMTP is not offered: an alert legitimately carries hostnames and failure text, and a relay
that does not offer STARTTLS is refused rather than downgraded to. The password comes from a file, or
from `FARRIER_SMTP_PASSWORD`, and never from a flag, because `argv` is world-readable in `ps`.

Without a relay, every other route still works — the event inbox, the live feed in the interface, and
each fleet's webhook — and a rule that names recipients says on the rule that its mail did not go out.

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
   chosen by the control plane would invalidate the signature.

   ```bash
   farrier sign --key ~/.farrier/ops.key --host 01J9ABC… \
     --intent service.restart --params '{"unit":"nginx.service"}' \
   | curl -sX POST "$FARRIER_URL/api/v1/jobs" \
       -H "Authorization: Bearer $FARRIER_ADMIN_TOKEN" \
       -H 'Content-Type: application/json' -d @-
   ```

   It shows you the operation, the host, the window and the exact bytes it is about to sign, and asks
   before signing. It never talks to the control plane: if it signed a digest the server handed it, a
   compromised control plane could display one operation and have another authorised.
2. Release, if your fleet asks for it — `POST /api/v1/jobs/{id}/approve`. Whether that is required at
   all, and whether the releaser must be somebody other than the job's creator, is your fleet's
   `approvalMode`. A new fleet requires nothing; see
   [`SECURITY.md` §3](SECURITY.md#3-the-intent-catalogue).

A **routine** job — `packages.applySecurity` — needs neither. The control plane signs it with its own
key, and what bounds it is your host's `updates.allow`: the worst the control plane can do is make a
host apply security updates sooner than its own timer would have.

## What a fresh host will and will not do

Straight after installation, before you change anything:

| | |
| --- | --- |
| Reports inventory, services, pending updates and reboot state | **yes** |
| Applies security updates on its own timer, via `unattended-upgrades` | **yes** — and it keeps doing this if the control plane is unreachable, or if you never enrol it at all |
| Applies security updates because the control plane asked | **only if `updates.allow` permits it** — the control plane signs the request, and the host's own policy decides |
| Applies *every* update because the control plane asked | **no** — `packages.applyAll` needs a signature from a key you place on the host |
| Applies updates because an administrator ran the helper on the host | only security updates, and only what the policy below allows |
| Restarts a service, or reboots | **no**, from anyone, until you change the two files below |
| Reports which of its units are in the failed state | **yes**, for every unit. `[services] watched` narrows which *changes* become events, not what is reported |
| Reports the containers running on it | **no**, until `[containers] report = true` |

The two files are the whole of it:

**`/etc/farrier/policy.toml`** — root-owned, a dpkg conffile, and the control plane cannot modify it.
It ships permitting security updates, no reboots, and no restartable units. Effective permission for
any job is `min(what the control plane asked for, what this file allows)` — never the maximum. Check an
edit with `farrier-agent policy check` before restarting anything: a file that does not parse makes the
host refuse all privileged work rather than fall back to a default, which is deliberate and is a
miserable way to discover a typo.

Two keys in it are the exception to everything the paragraph above says, because they bound what this
host *says* rather than what may be done to it. Neither is a permission, and neither involves a
signature.

`[services] watched` decides which unit-state changes become events, and its empty default means
*every* unit rather than none: permitting an action and reporting a fact are different questions, and a
fresh host should surface a failed unit rather than hide it. Narrowing it quietens a noisy machine;
widening it grants nothing.

`[containers] report` is the other way round: it ships `false`, and a host reports nothing about the
containers on it until somebody writes `true`. A container list describes what a business runs, which is
a different disclosure from a package count. Turning it on reports each container's id, its main
process's *name* — never its command line, which is where credentials end up — when it started, its
resource use, and four things `docker ps` will not tell you: whether it is privileged, whether its
seccomp filter is off, whether it runs as root, and whether the Docker socket is bind-mounted into it.
It cannot report image names, exit codes, restart counts or health, because those live behind the
socket that `farrier` is deliberately not in the group for.

Two practical notes. The resource figures change on every collection, so a host that opts in sends a
full report on every heartbeat rather than the digest it would otherwise send. And **upgrade the agent
before you add the key**: the policy parser refuses a file it does not understand and falls closed, so
writing `[containers]` into a host still running an older agent turns that host's update permission off
until the agent catches up.

**`/etc/farrier/trusted-signers`** — root-owned, a dpkg conffile, and **empty**. Every destructive
operation needs a signature from a key listed here, and the control plane holds none of them. Generate
one on your own machine:

```bash
farrier key generate --out ~/.config/farrier/signing.key --id ops-laptop
# prints the line to paste into /etc/farrier/trusted-signers on the hosts that key may act on
```

### Keys that are not files

A key file on a laptop is a real improvement over a shared credential and it is still a file: it can be
copied, and nobody would know. `--key` takes a reference rather than a path, so the same command signs
with a hardware token or a cloud key store, and `farrier key show --in <reference>` prints the
`trusted-signers` line for any of them.

```bash
# A PKCS#11 token — YubiKey PIV, Nitrokey, SoftHSM. The URI is RFC 7512, which is what
# OpenSSL, GnuTLS and p11-kit already speak, so an existing one can be pasted.
farrier key show --in "pkcs11:token=ops;object=ops-yubikey-1?module-path=/usr/lib/opensc-pkcs11.so"

# A cloud key store. The #fragment is the identity the audit log records and every host lists —
# a resource name is not one, and it is required rather than derived.
farrier key show --in "awskms:arn:aws:kms:eu-central-1:123456789012:key/abcd-1234#ops-kms-1"
farrier key show --in "gcpkms:projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1#ops-kms-1"
farrier key show --in "azurekms:ops.vault.azure.net/keys/farrier-signing/9885aa55#ops-kms-1"
```

A PIN is prompted for, or read from a file with `pin-source=/path`. It is never a URI attribute and
never a flag: a secret on a command line is readable from the process list by every user on the machine.

Cloud credentials come from the environment, then the provider's own well-known file, then the instance
metadata service — which is the order that answers promptly on a laptop, where the metadata address
does not refuse a connection but black-holes it. The flows that are not implemented, because they are
most of what a vendor SDK weighs, have one escape hatch each:

```bash
eval "$(aws configure export-credentials --profile ops --format env)"                    # SSO, assume-role, federation
export FARRIER_KMS_BEARER_TOKEN="$(gcloud auth print-access-token)"                       # workload identity
export FARRIER_KMS_BEARER_TOKEN="$(az account get-access-token   --resource https://vault.azure.net --query accessToken -o tsv)"                         # certificate auth, federation
```

**Where a cloud key lives matters more than which cloud it is in.** A KMS key the control plane's own
identity can call `Sign` on is a key the control plane holds, whatever the console says about custody —
see [`SECURITY.md` §9](SECURITY.md#9-what-farrier-does-not-defend-against). Put it in an account the
control plane has no role in, and check it the way that catches the mistake: assume the control plane's
identity and confirm that signing is denied.

Note that Azure Key Vault has no EdDSA algorithm at all, so a Key Vault key must be P-256 and its
`trusted-signers` line will read `ecdsa-p256`. AWS KMS and Cloud KMS can do either.

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
