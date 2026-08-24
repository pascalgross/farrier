# Running the control plane in containers

The control plane is one binary and PostgreSQL, and that is exactly what is in here: a `Dockerfile`
that builds `farrier-server` with the interface embedded, and a Compose stack of two services. Traefik
is optional and in its own file. A streaming replica is optional and in its own file too.

```
deploy/
├─ compose.yaml               postgres + farrier-server; works on its own
├─ compose.traefik.yaml       optional overlay: TCP router, TLS passthrough, for agents
├─ compose.traefik-ui.yaml    optional overlay: the interface on a second hostname, with ACME
├─ compose.standby.yaml       optional overlay: a streaming replica of the database
├─ .env.example               every value the stack needs, with the reasoning
├─ docker-entrypoint.sh       creates the CA on a first start, then serves
├─ traefik/dynamic/           the ServersTransport the interface overlay needs, for your Traefik
└─ postgres/
   ├─ farrier.conf            the settings that make replication possible without a restart later
   ├─ initdb/                 the ordinary role, the replication role, the pg_hba line
   └─ standby-entrypoint.sh   pg_basebackup on a first start, then an ordinary PostgreSQL
```

The agent is **not** here, and there is no image for it. It manages a host; a host it managed from
inside a container on the control plane would be the control plane. It installs from APT — see
[`../docs/INSTALL.md`](../docs/INSTALL.md).

`farrier`, the command that signs a destructive job, is not in the image either. That is the same
decision seen from the other side: a signing key the control plane's own host can reach is a key the
control plane holds, whatever the console says about custody. See
[`../docs/SECURITY.md`](../docs/SECURITY.md#9-what-farrier-does-not-defend-against).

## Starting it

```bash
cd deploy
cp .env.example .env      # fill in four passwords; `openssl rand -hex 32` for each
docker compose up -d      # builds the image from this checkout on the first run
docker compose logs -f farrier-server
```

The first start builds the image, initialises the cluster — the ordinary role, the database it owns,
the replication role and its `pg_hba.conf` line — then creates the certificate authority, migrates the
schema, and serves on `https://localhost:8443`. Nothing below is needed to get that far.

```bash
# The token is in your .env; the certificate is Farrier's own until you supply one, hence --insecure.
curl -sk https://localhost:8443/api/v1/hosts -H "Authorization: Bearer $FARRIER_ADMIN_TOKEN"
```

Requires Docker Compose v2.24 or newer, for the `!override` in the Traefik overlay.

## What is deliberate in here

**The server does not connect as `postgres`.** The image's `POSTGRES_USER` is the cluster's bootstrap
superuser, and PostgreSQL exempts a superuser — and any role with `BYPASSRLS` — from every row-level
security policy in the schema. Fleets are isolated from one another by exactly those policies, so a
control plane connected as that role does not have a weakened boundary, it has none, and every query
returns every fleet's rows with nothing looking wrong. `postgres/initdb/10-farrier-role.sh` creates an
ordinary role that owns its own database; `farrier-server` checks its own privileges at startup and
refuses to serve on either kind. See [`../docs/SECURITY.md`](../docs/SECURITY.md#5-tenants).

**The database password is not in the connection URL.** It is passed as `PGPASSWORD`, which libpq and
pgx read, because a URL is a parser and a password is arbitrary text: `/`, `#` and `?` make the URL fail
to parse, and `%` parses as an escape and silently means something else. The init script sets the
password through psql variables, where every character is legal — so without this the two halves
disagree, and the symptom is a control plane that cannot connect using the password the database
accepted. A password inside an explicit `FARRIER_DATABASE_URL` still wins, as libpq specifies.

**The CA directory is a volume, and it is not the database.** `farrier-state` holds three things: the
CA that issues agent certificates, the key that signs routine jobs, and the key that encrypts
provisioning template bodies at rest. None of them is in PostgreSQL, which is what makes a database dump
neither a way to impersonate a host nor a set of provisioning scripts. Back it up separately from the
database, and restore both — a database restored without `template.key` leaves every stored template
permanently unopenable, and the control plane says so rather than pretending they are corrupt.

**The container's uid is pinned at 65532.** A volume keeps the ownership it was created with, so a uid
that drifted between image releases would leave a running installation unable to read its own CA.

**The self-issued certificate expires, and a restart is what renews it.** When you pass no
`--tls-cert`, the server issues itself one from its own CA, valid ninety days, and replaces it on any
start once it is past sixty (`internal/ca/ca.go`). A container left running for more than ninety days
therefore serves an expired certificate, and every agent stops trusting it at once. Either give the
interface its own hostname and certificate as above, or restart the control plane every couple of
months — `docker compose restart farrier-server` is enough, and agents ride it out on their backoff.

**`archive_mode` is on and archives nothing.** It cannot be turned on without restarting the cluster,
while the command it runs is a reload — so this is what makes point-in-time recovery a configuration
change later rather than a maintenance window on a primary with a standby attached. Until you replace
`archive_command`, it is `/bin/true`: visibly a no-op, rather than an archive that turns out at restore
time to be empty.

## Traefik

```bash
docker network create traefik      # if it does not exist yet
docker compose -f compose.yaml -f compose.traefik.yaml up -d
```

The overlay adds a **TCP** router with `tls.passthrough=true`, not an HTTP one, and removes the
published port. Traefik matches SNI and forwards bytes; the TLS session runs end to end between the
agent and `farrier-server`.

That is not a preference. The agent protocol authenticates a host with a client certificate, and the
server identifies the host by that certificate's fingerprint on every request — which is also the whole
revocation mechanism, since there is no CRL and no OCSP. A proxy that terminated TLS would end the
connection carrying the certificate and open one that does not, leaving the server two options: refuse
every agent, or believe a header. Believing a header would mean anything able to reach the proxy's back
end can claim to be any enrolled host, which is the guarantee in
[`../docs/SECURITY.md`](../docs/SECURITY.md) §1 traded for a certificate resolver.

Three consequences worth knowing before you deploy it:

- **The certificate a browser sees is the server's, not Traefik's.** On a default installation it is
  issued by Farrier's own CA and the browser will say so. Mount a real certificate and pass
  `--tls-cert`/`--tls-key` — the commented block in the overlay — or live with the warning on an
  installation only you use. Agents are unaffected either way: an agent verifies against the CA bundle
  it was handed at enrolment.
- **A certificate resolver on this router does nothing.** There is nothing for Traefik to terminate.
- **Every agent arrives from Traefik's address.** Enrolment is rate limited per source address — twenty
  attempts, one returning every three seconds — and behind a proxy the fleet shares one bucket. The
  limiter answers 429 with a `Retry-After` rather than failing, so this costs time rather than
  enrolments; provisioning more than twenty hosts at once is a reason to enrol against the published
  port directly. The limiter ignores `X-Forwarded-For` on purpose: a header the client sets is not a
  source address, and trusting one would look like a defence while being none.

### Let's Encrypt, on a second hostname

Traefik's certificate resolver is useless on the router above — there is nothing for it to terminate.
The way to a browser-trusted certificate is therefore not to bring one to that router, but to give the
interface a hostname of its own where Traefik does terminate:

```
agents.example.org   TCP router, passthrough   → agents, mTLS end to end, Farrier's own certificate
farrier.example.org  HTTP router, ACME         → operators, in a browser, Let's Encrypt
```

What makes this the cheap answer rather than a compromise is that **agents do not need a publicly
trusted certificate at all.** They verify the control plane against the CA bundle handed to them at
enrolment, so Let's Encrypt lands on exactly the audience it helps and on nothing else. No certificate
reaches the container either: Traefik renews on its own, while `farrier-server` reads `--tls-cert` once
at startup, so a certificate fed to it would need a restart on every renewal.

The two names must be different. One hostname cannot be both, because a TCP router whose `HostSNI`
matches wins the connection before any HTTP router sees it — the interface would simply never answer.

Three things in your Traefik, once:

```bash
# 1. Farrier's CA certificate, so the leg from Traefik to the container is verified rather than skipped.
docker compose cp farrier-server:/var/lib/farrier-server/ca/ca.crt ./farrier-ca.crt

# 2. Mount it at /etc/traefik/farrier-ca.crt, and traefik/dynamic/farrier.yml into the directory
#    Traefik watches (providers.file.directory). A label cannot declare a ServersTransport.

# 3. Bring the stack up with both overlays.
docker compose -f compose.yaml -f compose.traefik.yaml -f compose.traefik-ui.yaml up -d
```

**Copy `ca.crt`; do not mount the `farrier-state` volume into Traefik.** That volume also holds
`ca.key`, the key that signs routine jobs and the key that seals template bodies. A proxy that could
read `ca.key` could issue client certificates and impersonate any host to this control plane —
[`../docs/SECURITY.md`](../docs/SECURITY.md) names the CA key and the database as exactly the pair that
buys that. `ca.crt` is a public document and is the whole of what Traefik needs.

The `serverName: localhost` in that snippet is not a workaround. The container's certificate is issued
by Farrier's own CA and names `localhost`, `127.0.0.1` and `::1`; the public name is on Traefik's
certificate, not on the server's. Overriding the name Traefik expects is what turns that leg into a real
verification instead of an `insecureSkipVerify`.

The overlay also refuses `/agent` on the interface hostname, with a 403 from the proxy. Those endpoints
would answer 401 there anyway — terminated TLS carries no client certificate — but a hostname with no
path to the agent API is one where no later middleware or header can become one. Point agents at the
passthrough name.

## Replication

The primary is configured for it from the first start: `wal_level = replica`, ten walsenders, ten
replication slots, `wal_keep_size = 1GB`, `wal_log_hints = on` for `pg_rewind`, a `replicator` role,
and the `pg_hba.conf` line that lets it in. None of that can be added later without either a restart or
a reload of a primary that is already serving, which is why it is on before anybody wants it.

```bash
docker compose -f compose.yaml -f compose.standby.yaml up -d
```

The standby's first start takes a base backup with `pg_basebackup --create-slot --wal-method=stream`,
writes its own recovery configuration, and comes up in hot standby. Check it from the primary:

```bash
docker compose exec postgres psql -U postgres -x -c \
  "SELECT client_addr, state, sync_state, replay_lag FROM pg_stat_replication;"
```

`state` reads `streaming` when it is caught up. The replication password is written to a `.pgpass` in
the standby rather than into `primary_conninfo`, because `postgresql.auto.conf` ends up in that
standby's own base backups and in anything that copies its data directory.

**Nothing here fails over, and that is the design.** A pair that promotes itself becomes two primaries
during a network partition, and reconciling those means deciding which fleet's job results to discard.
Promotion is a decision somebody makes:

```bash
docker compose exec postgres-standby pg_ctl promote -D /var/lib/postgresql/data
# then point FARRIER_DATABASE_URL at it and restart farrier-server
```

The old primary is then a cluster that diverged. `wal_log_hints` is on so that `pg_rewind` can bring it
back as a standby of the new primary; without it, the only route back is a fresh base backup of a
database that was never broken.

**A standby is not a backup.** It replicates a mistaken `DELETE` as faithfully as anything else. What
protects against that is `archive_command` pointing somewhere durable plus periodic base backups — and
a restore rehearsed at least once, because an archive nobody has restored from is a belief rather than
a backup.

Retiring a standby means dropping its slot on the primary, or the primary keeps WAL for a replica that
is never coming back until the volume fills:

```bash
docker compose exec postgres psql -U postgres -c "SELECT pg_drop_replication_slot('standby1');"
```

### Turning archiving on

Give the primary somewhere to write that survives it — a mounted volume, an object store through a tool
like WAL-G or pgBackRest — then set `archive_command` in `postgres/farrier.conf` and reload:

```bash
docker compose exec postgres psql -U postgres -c "SELECT pg_reload_conf();"
```

Two properties any command you write must have. It has to **fail loudly**: PostgreSQL retries a failing
`archive_command` for ever and keeps the WAL meanwhile, so a broken archive eventually fills the data
volume — which is bad, and is much better than the alternative. And it must not overwrite: `test ! -f
<dest> && cp %p <dest>` is the shape, because an archive that silently replaces a file is one where the
segment you need has been replaced by a different segment with the same name.

If the volume you archive to is a Docker volume, create it with the right ownership before pointing
anything at it. Docker creates a missing mount point as `root`, and PostgreSQL runs as uid 999 in this
image — an `archive_command` that cannot write is the failure above, arriving on a schedule.

## Applying a change

```bash
docker compose up -d --build             # rebuild the image and restart the server
docker compose restart postgres          # after editing postgres/farrier.conf
docker compose exec postgres psql -U postgres -c "SELECT pg_reload_conf();"   # for settings that reload
```

`postgres/farrier.conf` is read on every start because `initdb` appended an `include_if_exists` line to
the generated `postgresql.conf` on the very first start. An existing cluster that predates this file
needs that line added once, by hand:

```bash
docker compose exec postgres bash -c \
  "echo \"include_if_exists = '/etc/postgresql/farrier.conf'\" >> \$PGDATA/postgresql.conf"
docker compose restart postgres
```

The `initdb` scripts run **only** on an empty data directory. Changing a password in `.env` afterwards
changes nothing on its own: change it in SQL with `ALTER ROLE`, and in `.env`, in that order.

## Upgrading PostgreSQL across a major version

The data directory of one major version is not readable by the next, so bumping the `image:` line alone
produces a container that restart-loops with the reason in a log nobody is watching. Dump and restore,
or run `pg_upgrade` deliberately; with a standby, upgrade the primary and rebuild the standby, in that
order. This is the reason both files pin a major version rather than tracking `postgres:latest`.

## Checking the whole thing

```bash
make compose-check    # every Compose file, and both overlays, parse
make image            # build the image the stack runs
docker compose exec farrier-server farrier-server catalogue
```

The last one is worth running once against a running container. It prints the complete, closed set of
operations this build can ask a host for, plus the list this project has permanently refused to
implement — which is the fastest way to check the claim on the front page against the binary you are
actually running, rather than against the one somebody documented.
