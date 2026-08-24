# Farrier agent protocol, version 1

This document specifies the wire protocol between a Farrier agent and a Farrier control plane
completely enough that a third party could write an interoperable agent without reading Farrier's
source. Where this document and the implementation disagree, that is a bug in one of them; please
report it.

Companion documents: [`SECURITY.md`](SECURITY.md) for why the protocol is shaped this way.

## 0. Conventions

- All request and response bodies are UTF-8 JSON with `Content-Type: application/json`.
- Timestamps are RFC 3339 with an explicit offset, always `Z` in practice.
- Durations named `...Seconds` are integers.
- Unknown response fields **must** be ignored by agents, so the control plane can add fields without a
  fleet-wide agent upgrade. Unknown request fields **must** be ignored by servers, for the reverse.
- The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

## 1. Shape of the protocol

**The agent always initiates. There is no server→agent direction.** A managed host opens no listening
port for Farrier and needs no inbound firewall rule.

The transport is **HTTPS with mutual TLS**, using long-polling for job delivery. This is chosen over
WebSocket and gRPC deliberately: Farrier's jobs are hours apart, so the latency win of a persistent
duplex stream is worth nothing, while ordinary HTTPS passes through every corporate proxy, terminates
on every load balancer, and — the property that matters most during an incident — reproduces exactly
with `curl`.

There are exactly five endpoints. Four are the steady-state protocol; the fifth is certificate
renewal.

```
POST /agent/v1/enroll             bootstrap token + CSR -> host-scoped client certificate
POST /agent/v1/heartbeat          every ~60s, digest-first
GET  /agent/v1/jobs?wait=25       long-poll, woken early by NOTIFY farrier_job
POST /agent/v1/jobs/{id}/result   idempotent, retried, survives reboot
POST /agent/v1/renew              re-key at 2/3 of certificate lifetime
```

No other endpoint is part of the agent protocol. In particular there is no endpoint by which the
server pushes anything, and no endpoint that accepts an executable payload.

## 2. Authentication

### 2.1 Enrolment

`POST /agent/v1/enroll` is the only unauthenticated-by-certificate call. It is authorised by a
**bootstrap token**: a single-use, time-limited, control-plane-issued opaque string.

Tokens are compared in constant time and are consumed on first successful use. A token that has been
used, expired, or revoked MUST be rejected with `401`, with no distinction between those cases in the
response body — telling an attacker which of the three applies is free reconnaissance.

### 2.2 Steady state

Every other call requires a **client certificate** issued by the control plane's private CA, scoped to
one host. The server MUST, on every request:

1. verify the certificate chains to its CA and is within its validity window;
2. extract the host identity from the certificate subject;
3. look up that certificate's **SHA-256 fingerprint in the database** and reject if it is absent or
   marked revoked.

Step 3 is the revocation mechanism. Farrier deliberately uses neither CRL nor OCSP: a database check
that already has to happen is instant, has no distribution delay, and has no stapling infrastructure
to misconfigure.

### 2.3 Certificates

- Agent certificates are valid for **90 days**.
- The agent renews at **two thirds of lifetime** (60 days), with jitter, via `POST /agent/v1/renew`
  authenticated by the certificate currently in force.
- Renewal issues a new certificate for the same host identity; the agent MUST write the new key and
  certificate atomically (write to a temporary file in the same directory, `fsync`, `rename`) and MUST
  keep using the old pair until the new one is durably on disk.
- The private key never leaves the host. Enrolment and renewal both send a CSR.

## 3. `POST /agent/v1/enroll`

### Request

```json
{
  "token": "opaque-single-use-string",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "hostname": "web-01",
  "machineIdHash": "sha256:9f2c...",
  "agentVersion": "0.1.0",
  "requestedBootstrap": "standard-server"
}
```

`machineIdHash` is `SHA-256(salt || /etc/machine-id)`, where the salt is generated on the host at
install time and stored in `/var/lib/farrier/machine-id-salt`. The raw `/etc/machine-id` value is
documented by systemd as confidential and MUST NOT be transmitted.

A `machineIdHash` is claimed by at most one host that has not been revoked. Revoking a host, or
deleting it, releases the claim and lets that machine enrol again under a new host id; a revoked host
keeps its row and its history, so releasing the machine does not cost the audit trail. A server MUST
record the host and its first certificate atomically — a host row whose certificate failed to record
would hold the claim while being unable to authenticate, wedging that machine permanently.

`requestedBootstrap` is present only when the operator passed `--bootstrap NAME`, and is subject to
every guardrail in [`SECURITY.md` §7](SECURITY.md#7-provisioning-and-the-enrolment-time-exception).

### Response `200`

```json
{
  "hostId": "01J9...",
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "caBundle": "-----BEGIN CERTIFICATE-----\n...",
  "serverTime": "2026-08-22T14:00:00Z",
  "nextHeartbeatSeconds": 60,
  "bootstrap": {
    "name": "standard-server",
    "version": 3,
    "body": "#cloud-config\n...",
    "signature": "base64...",
    "signerKeyId": "ops-yubikey-1"
  }
}
```

`bootstrap` is present only if it was requested. `signature` covers the canonical encoding of

```json
{"body":"…","name":"…"}
```

(keys in canonical order, per [§8](#8-canonical-json)). The name is covered as well as the body: signing
the body alone would let a compromised control plane return a genuinely signed template that the
operator did not name. `version` is informational and deliberately outside the signed payload — the
record on the host keeps the body verbatim, so what ran stays knowable from the host alone even if a
control plane relabelled its version numbers. The server issues a template only when the enrolment
token was minted naming it, and refuses the enrolment — before consuming the token — when the named
template is missing or unsigned, because an agent that asked and silently received nothing must not
proceed as though something had been applied.

The agent MUST verify the signature against a key present in the host's **existing**
`/etc/farrier/trusted-signers` before doing anything with `body`; MUST refuse if `name` is not the name
the operator asked for; MUST print the template and record it to journald and
`/var/lib/farrier/bootstrap-applied.json` before executing it; and MUST refuse entirely if
`trusted-signers` is empty. It MUST NOT fall back to trusting the server.

The body is printed **escaped**, not raw. It comes from the control plane, and a raw body can carry
terminal control sequences that scroll the real content out of view, or a line that reproduces the
end-of-template marker followed by something else — so that the operator reads one template and
approves another.

### Errors

| Status | Meaning |
| --- | --- |
| `400` | Malformed body or CSR |
| `401` | Token unknown, expired, or already used |
| `409` | A host with this `machineIdHash` is already enrolled |
| `429` | Rate limited; honour `Retry-After` |

## 4. `POST /agent/v1/heartbeat`

Sent every `nextHeartbeatSeconds` (default 60), with full jitter.

### 4.1 Digest-first

The steady-state heartbeat carries **digests, not inventory**:

```json
{
  "agentVersion": "0.1.0",
  "bootId": "b1e5...",
  "uptimeSeconds": 84231,
  "factsDigest": "sha256:5a1c...",
  "policyDigest": "sha256:77b0...",
  "signersDigest": "sha256:4f53...",
  "clockOffsetSeconds": 0,
  "paused": false,
  "signers": null
}
```

`signersDigest` is the digest of the host's trusted key set. It exists so that an operator can see that
hosts which should have the same signers do, **without any host transmitting its trust anchor
anywhere**; a fleet where one machine quietly has an extra key is exactly what it makes visible.

`signers` carries no `omitempty` and is `null` in the steady state. An **empty** trust anchor is the
shipped default and the most important thing that field can say — "this host will execute nothing
destructive" — so it must be distinguishable on the wire from "the host did not report". With
`omitempty` the two are identical, and a server would ask for a document the agent had already sent, on
every heartbeat, for the life of every unconfigured host in the fleet.

The server compares the digests to what it has stored and replies:

```json
{
  "serverTime": "2026-08-22T14:00:00Z",
  "nextHeartbeatSeconds": 60,
  "wantFullReport": false,
  "wantFacts": false,
  "wantPolicy": false,
  "wantSigners": false
}
```

A server MUST record a digest only for a document it has actually received. Recording the digest a host
*claimed* makes the comparison compare a claim against itself: the server asks once, and if that one
full report is lost to a network failure it concludes on the next heartbeat that it is up to date and
never asks again — while the document it believes it holds has never existed. Nothing about that
failure is visible from either side.

When `wantFullReport` is true — or when either specific `want*` flag is set — the agent includes the
corresponding full payload on its **next** heartbeat.

This matters at scale, and skipping it is a production incident rather than an inefficiency. Five
hundred hosts sending a full inventory every 60 seconds is hundreds of kilobytes per host per minute
of write amplification on the control plane's database; digest-first makes the steady state hundreds
of bytes per host per minute, and full reports become rare and event-driven.

Digests are computed over the same canonical JSON encoding used for signing ([§8](#8-canonical-json)),
so an agent and a server that agree on the encoding agree on the digest.

### 4.2 Full report

```json
{
  "agentVersion": "0.1.0",
  "bootId": "b1e5...",
  "uptimeSeconds": 84231,
  "factsDigest": "sha256:5a1c...",
  "policyDigest": "sha256:77b0...",
  "clockOffsetSeconds": 0,
  "paused": false,
  "facts": {
    "hostname": "web-01",
    "distribution": {
      "id": "ubuntu", "family": "ubuntu", "codename": "noble",
      "version": "24.04", "prettyName": "Ubuntu 24.04.1 LTS", "supported": true
    },
    "kernel": "6.8.0-40-generic",
    "architecture": "amd64",
    "reboot": {
      "required": true,
      "reasons": ["linux-image-6.8.0-40-generic"],
      "services": ["ssh.service"],
      "serviceScanComplete": false,
      "source": "/var/run/reboot-required, needrestart (KSTA 3)"
    },
    "subscription": { "applicable": true, "attached": false, "services": {} },
    "packages": { "upgradableSecurity": 3, "upgradableTotal": 11 },
    "services": [{
      "name": "nginx.service", "loadState": "loaded",
      "activeState": "active", "subState": "running"
    }],
    "extra": { "network": { "interfaces": [{ "name": "eth0", "mtu": 1500, "up": true }] } }
  },
  "policy": { "...": "the effective parsed policy, for display and for min() checks server-side" },
  "signers": [{ "keyId": "ops-yubikey-1", "algorithm": "ed25519", "backend": "pkcs11" }]
}
```

Three fields inside `reboot` are worth reading carefully. `source` names which signal produced the
answer, because the two — the `/var/run/reboot-required` marker and `needrestart` — are present on
different distributions and a wrong answer needs to be traceable to its input rather than argued about.
`serviceScanComplete` reports whether the `needrestart` scan could see every process: the agent is
deliberately unprivileged, so it usually could not, and **"no services need restarting" and "I could not
see the services that do" must never look the same in a dashboard**.

`extra` holds the output of registered collectors, keyed by collector name. It is where a fact added
through the `collect.Collector` seam appears; see [`EXTENDING.md`](EXTENDING.md).

`signers` carries key identities and algorithms only — never keys, and never the file. The control
plane has no business holding a copy of a host's trust anchor, and rendering "ops-yubikey-1 (PKCS#11)"
in an audit trail needs no more than this.

`subscription.applicable` is `false` on Debian, where Ubuntu Pro and Livepatch do not exist. Clients
rendering this MUST show "not applicable" rather than "unknown" or an empty amber badge; a Debian host
that permanently displays an ESM warning teaches operators to ignore the dashboard.

### 4.3 Server-set pacing

`nextHeartbeatSeconds` is authoritative and MAY change on any response. It exists so a control plane
can spread load across the minute or back the whole fleet off during an incident **without deploying a
new agent**. Agents MUST honour it, clamped to a sane local range (Farrier's agent clamps to 15–3600
seconds) so that a compromised or buggy server cannot induce a hot loop.

### 4.4 `serverTime` and clock skew

`serverTime` is used **solely** to compute and report `clockOffsetSeconds`. The agent MUST NOT adjust
its clock, its timers, or any validity check to server-supplied time. Signature `notBefore`/`notAfter`
are always evaluated against the local clock.

When `|clockOffsetSeconds| > 300`:

- read-only intents still execute;
- privileged intents **refuse** (fail closed) with a distinguishable error;
- the server flags the host in the UI.

### 4.5 Bounds

| Limit | Value |
| --- | --- |
| Heartbeat request body | 1 MiB |
| Services reported | 500 |
| Upgradable packages listed | 500 |
| `rebootRequiredBy` entries | 100 |

Servers MUST reject over-size bodies with `413`. Agents MUST truncate rather than emit an over-size
body, and MUST set a `truncated` flag on the affected section. In multi-tenant hosting, one host
filling the database fills it for other customers.

## 5. `GET /agent/v1/jobs?wait=25`

Long-poll. The server holds the connection for up to `wait` seconds, returning early as soon as a job
is available for this host. Internally the wake-up is a Postgres `LISTEN`/`NOTIFY` on channel
`farrier_job`; that is an implementation detail, not part of the wire contract.

- `wait` is clamped by the server to `[0, 60]`.
- The default and recommended value is **25 seconds**. It must sit below the smallest idle timeout on
  the path; 30–60 seconds is the common default for proxies, load balancers and NAT tables, and a hold
  longer than that produces mysterious intermittent failures that look like network flakiness.
- `wait=0` degrades to plain polling, for environments that terminate held connections.

### Response `200` — no work

```json
{ "jobs": [] }
```

### Response `200` — work available

```json
{
  "jobs": [
    {
      "id": "01J9ABC...",
      "intent": "packages.applySecurity",
      "params": {},
      "class": "routine",
      "issuedAt": "2026-08-22T13:59:58Z",
      "notBefore": "2026-08-22T14:00:00Z",
      "notAfter":  "2026-08-22T14:30:00Z",
      "nonce": "b64...",
      "signature": "b64...",
      "signerKeyId": "farrier-online-1",
      "signerAlgorithm": "ed25519"
    }
  ]
}
```

A job is a *typed intent with typed parameters*. It is never a command, a script, a path to execute, or
a URL to fetch code from. An agent receiving an `intent` it does not recognise MUST report
`unsupported_intent` and MUST NOT attempt any fallback interpretation.

`id` is letters and digits only, at most 64 of them. For an unsigned job the control plane generates
it; for a signed one the signer chooses it, and the control plane MUST refuse a request whose `id` is
any other shape rather than correcting it — the signature covers the id, so a normalised id would not
verify. The rule exists because the id is a path segment in [§6](#6-post-agentv1jobsidresult) and a
filename in the agent's result spool: an id containing `/`, `?` or `#` yields work whose result has
nowhere to go.

### 5.1 Agent-side acceptance checks

Before executing anything, the agent MUST, in this order, and MUST fail closed on any error:

1. **Recognise the intent** against its compiled-in catalogue.
2. **Validate the parameters** against that intent's validator. A unit name must match
   `^[a-zA-Z0-9@._-]+\.(service|socket|timer)$`; anything else is rejected without execution.
3. **Refuse privileged intents if the clock is too far out** — see [§4.4](#44-servertime-and-clock-skew).
   This comes *before* the validity-window check, not after: a host whose clock is an hour wrong would
   otherwise report every privileged job as `expired`, which sends an operator looking at the control
   plane's scheduling rather than at the host's clock. A refusal should name its cause.
4. **Check `notBefore`/`notAfter` against the local clock**, never against server-supplied time.
5. **Check the class**:
   - `read` — no signature required, mTLS is sufficient;
   - `routine` — signature by the control plane's online key required. An agent MUST NOT execute a
     routine intent until it verifies that signature: routine is the one class for which no offline
     signature is required, so an agent that skipped the check would be acting on mTLS alone. The key
     is delivered to the agent in the enrolment response and refreshed on every heartbeat
     ([§4](#4-post-agentv1heartbeat)); an agent that has not been given one refuses routine intents
     with `refused_unsigned`. **A signature by a key in `trusted-signers` is not an online-key
     signature** and MUST NOT be accepted as one;
   - `destructive` — signature by a key present in this host's `/etc/farrier/trusted-signers`
     required. A signature by the online key is **not** acceptable for this class.
6. **Verify the signature** over the canonical payload ([§8](#8-canonical-json)), then **check the
   nonce** against the persisted nonce store and refuse replays. In that order: recording the nonce
   first would let anyone who can reach the agent burn one with a garbage signature, and the store is
   persistent, so the genuine job bearing that nonce would be refused as a replay for as long as its
   signature remained valid.
7. **Check job age** against the local policy's `limits.max_job_age_seconds`.
   `issuedAt` is **not** covered by the signature (see [§8](#8-canonical-json)), so for a signed job the
   age is measured from `notBefore`, which is. A control plane that has been taken over could otherwise
   defeat the age limit entirely by setting `issuedAt` to the current time, which is the one thing that
   limit exists to prevent.

8. **Check the local policy** for whatever the intent needs — and then hand off to the root helper,
   **which checks the policy again itself**. The agent-side check is an optimisation and a better
   error message; the helper's check is the one that is load-bearing, because it runs as root against
   the root-owned file and does not trust its caller.

### 5.2 The control plane's online key

The enrolment response ([§3](#3-post-agentv1enroll)) and every heartbeat response
([§4](#4-post-agentv1heartbeat)) MAY carry `onlineKey`: the control plane's own public key, in the same
one-line format as a host's `trusted-signers` file.

```
ed25519 MCowBQYDK2VwAyEA… farrier-online-4f2a91c3 control-plane
```

An agent caches it and verifies routine intents against it. Three rules:

- It is sent on every heartbeat rather than digest-first, unlike the facts, policy and signers
  documents. Those are kilobytes; this is one line, and sending it unconditionally means rotation
  propagates with no state machine and no host stranded on a key that no longer verifies.
- An **absent or empty** field means "nothing to say", never "forget your key". An agent MUST keep what
  it has. The other reading would let one malformed response disable a fleet's routine tier.
- It is cached as *state*, not as a trust anchor. Farrier's agent keeps it in
  `/var/lib/farrier/online-key` and never in `/etc/farrier`, because `/etc/farrier/trusted-signers` is
  what an administrator decided and this is what a control plane said.

That the control plane distributes the key it signs with is acceptable **only** because of what the
routine tier is bounded by. See [`SECURITY.md` §3](SECURITY.md#3-the-intent-catalogue): a routine intent
can at most make a host do sooner what its own local policy already permits it to do unattended, and the
root helper re-reads that policy itself. The same arrangement for the destructive tier would be a
backdoor, which is why an agent MUST verify the two against different anchors.

## 6. `POST /agent/v1/jobs/{id}/result`

```json
{
  "jobId": "01J9ABC...",
  "status": "succeeded",
  "startedAt":  "2026-08-22T14:00:03Z",
  "finishedAt": "2026-08-22T14:02:11Z",
  "exitCode": 0,
  "output": "…last 64 KiB…",
  "outputTruncated": false,
  "result": { "…": "intent-specific typed result" },
  "error": null
}
```

`status` is one of `succeeded`, `failed`, `refused_by_policy`, `refused_unsigned`, `refused_clock_skew`,
`unsupported_intent`, `expired`. The set is closed and the control plane **MUST** reject any other word
with `400`, because every client renders `status` as the job's state: a host that could report `queued`
could make a job it had already run look untouched. An agent that meets a `400` here has produced a
result this control plane cannot store; it logs and drops it like any other `400`, per
[§11](#11-errors).

### 6.1 Idempotency

Results are **keyed by job id** and MUST be idempotent server-side: a repeated `POST` for a job whose
result is already recorded returns `200` and changes nothing. Agents retry with full-jitter backoff
until they receive a `2xx`.

The agent persists the pending result to disk before its first send attempt and deletes it only after
a `2xx`. **Work that succeeded but whose result was lost must never re-execute** — that is how a
"retry" turns one reboot into a reboot loop.

### 6.2 Results must survive a reboot

`host.reboot` completes by the host disappearing, which means the naive implementation never reports
anything. The agent MUST:

1. write the pending result to `/var/lib/farrier/pending-results/<jobId>.json`, `fsync` it, and
   `fsync` the containing directory,
2. **then** invoke `/usr/libexec/farrier/reboot-host`,
3. and on next start, before anything else, scan that directory and deliver everything in it.

The same mechanism covers an agent restarted mid-upgrade, a control plane that was down when the job
finished, and a machine that lost power.

### 6.3 Output bounds

`output` is truncated to the **last 64 KiB**, with `outputTruncated` set. The tail is kept rather than
the head because the failure is at the end.

## 7. `POST /agent/v1/renew`

Authenticated by the current client certificate.

```json
{ "csr": "-----BEGIN CERTIFICATE REQUEST-----\n..." }
```

Response `200`:

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "caBundle": "-----BEGIN CERTIFICATE-----\n...",
  "notAfter": "2026-11-20T14:00:00Z"
}
```

The server MUST issue only for the host identity in the presenting certificate. It MUST NOT honour a
CSR whose subject names a different host.

## 8. Canonical JSON

Signatures and digests are computed over a canonical encoding, so that two implementations produce
byte-identical input:

- object keys sorted by Unicode code point, ascending;
- no insignificant whitespace;
- no trailing newline;
- strings in shortest-form escaping, UTF-8, with `<`, `>` and `&` **not** escaped;
- integers rendered without a decimal point or exponent; the protocol contains no floating-point
  values, and an implementation encountering one in a signed payload MUST reject it rather than guess
  at a rendering.

The signed payload for a job is exactly:

```json
{"hostId":"…","intent":"…","jobId":"…","nonce":"…","notAfter":"…","notBefore":"…","params":{…}}
```

(keys shown in canonical order). Signature algorithms are named on the wire: `ed25519` or `ecdsa-p256`.

**The signing request handed to `farrier sign` contains this full payload, not a digest of it.** That
is a requirement on the wire format, not a nicety of the CLI: if the operator's signing tool signed an
opaque digest supplied by the server, a compromised control plane could display one job in the browser
and have a different one signed. `farrier sign` decodes and renders the request **offline, without
contacting the server**, and what it renders is what it signs.

## 9. Backoff and startup

- All retries use **full-jitter exponential backoff**: `sleep = random(0, min(cap, base * 2^attempt))`.
  Not equal jitter, not decorrelated — full jitter, because the failure mode being prevented is
  synchronisation, and only full jitter removes it entirely.
- After boot, the agent waits a **uniformly random delay** before its first contact.
- Base 1 s, cap 300 s, for both the heartbeat and the job poll.

Five hundred agents reconnecting in the same second is the single most common way an agent fleet kills
its own control plane, and it happens precisely when the control plane has just come back and is least
able to absorb it.

## 10. Offline behaviour

When the control plane is unreachable, the agent keeps running and the **host keeps patching from its
local policy**, because `unattended-upgrades` runs on its own systemd timer and does not need Farrier
to be reachable. Farrier's job is to observe and to schedule, not to be a dependency of the host
staying patched.

A control-plane outage must never mean an unpatched fleet. An agent that stopped patching when it
could not phone home would have made the fleet less safe by being installed.

## 11. Errors

| Status | Where it is returned | Agent behaviour |
| --- | --- | --- |
| `400` | Any endpoint, for a body that does not parse | Log and drop. An unparseable request will not become parseable on a retry |
| `401` | Any authenticated endpoint | Certificate rejected or revoked. Stop calling; log loudly. Do **not** re-enrol automatically — a host that re-enrols itself on `401` is a host an attacker can cause to re-enrol. Keep patching from local policy |
| `404` | `POST /jobs/{id}/result` | The job does not exist, or belongs to another host. Drop the result |
| `409` | `POST /enroll` | A host with this `machineIdHash` is already enrolled. Stop and require operator action: revoking or deleting the existing host releases the machine |
| `413` | `POST /heartbeat`, `POST /jobs/{id}/result` | Body too large. Truncate further, set the affected section's truncated flag, retry once, then drop |
| `429` | `POST /enroll` | Honour `Retry-After`, then full-jitter backoff. Only enrolment is rate limited: it is the one endpoint reachable without a client certificate, and throttling an authenticated fleet is a good way to break it during the incident when every host reconnects at once |
| `5xx` | Any endpoint | Full-jitter backoff, retry indefinitely |

A server MUST distinguish `400` from `413`. Returning one status for both makes a malformed body look
like an over-size one, and an agent following this table will keep truncating and retrying something
that will never parse.

Servers SHOULD return a problem body of `{"error":"code","message":"human text"}` but agents MUST NOT
require it, and MUST NOT parse `message` for control flow.

## 12. Versioning

The path segment `v1` changes only for a breaking change. Additive changes — new response fields, new
intents, new result fields — do not bump it, which is why both sides ignore unknown fields.

An agent that receives an intent it does not know reports `unsupported_intent`; the control plane uses
that, plus `agentVersion`, to decide what to schedule. Old agents are therefore safe to leave running:
they refuse what they do not understand rather than guessing.
