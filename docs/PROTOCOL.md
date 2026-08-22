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

`requestedBootstrap` is present only when the operator passed `--bootstrap NAME`, and is subject to
every guardrail in [`SECURITY.md` §6](SECURITY.md#6-provisioning-and-the-enrolment-time-exception).

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
    "body": "#cloud-config\n...",
    "signature": "base64...",
    "signerKeyId": "ops-yubikey-1"
  }
}
```

`bootstrap` is present only if it was requested. The agent MUST verify `signature` against a key
present in the host's **existing** `/etc/farrier/trusted-signers` before doing anything with `body`,
MUST print `body` in full and record it to journald and
`/var/lib/farrier/bootstrap-applied.json` before executing it, and MUST refuse entirely if
`trusted-signers` is empty. It MUST NOT fall back to trusting the server.

### Errors

| Status | Meaning |
| --- | --- |
| `400` | Malformed body or CSR |
| `401` | Token unknown, expired, or already used |
| `409` | A host with this `machineIdHash` is already enrolled and not marked for re-enrolment |
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
  "clockOffsetSeconds": 0,
  "paused": false
}
```

The server compares the digests to what it has stored and replies:

```json
{
  "serverTime": "2026-08-22T14:00:00Z",
  "nextHeartbeatSeconds": 60,
  "wantFullReport": false,
  "wantFacts": false,
  "wantPolicy": false
}
```

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
    "distribution": { "id": "ubuntu", "codename": "noble", "version": "24.04" },
    "kernel": "6.8.0-40-generic",
    "architecture": "amd64",
    "rebootRequired": true,
    "rebootRequiredBy": ["linux-image-6.8.0-40-generic"],
    "needrestartServices": ["ssh.service"],
    "subscription": { "applicable": true, "attached": false, "services": {} },
    "packages": { "upgradableSecurity": 3, "upgradableTotal": 11 },
    "services": [{ "name": "nginx.service", "activeState": "active", "subState": "running" }]
  },
  "policy": { "...": "the effective parsed policy, for display and for min() checks server-side" }
}
```

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

### 5.1 Agent-side acceptance checks

Before executing anything, the agent MUST, in this order, and MUST fail closed on any error:

1. **Recognise the intent** against its compiled-in catalogue.
2. **Validate the parameters** against that intent's validator. A unit name must match
   `^[a-zA-Z0-9@._-]+\.(service|socket|timer)$`; anything else is rejected without execution.
3. **Check the class**:
   - `read` — no signature required, mTLS is sufficient;
   - `routine` — signature by the control plane's online key required;
   - `destructive` — signature by a key present in this host's `/etc/farrier/trusted-signers`
     required. A signature by the online key is **not** acceptable for this class.
4. **Verify the signature** over the canonical payload ([§8](#8-canonical-json)).
5. **Check the nonce** against the persisted nonce store; refuse replays.
6. **Check `notBefore`/`notAfter` against the local clock** (see [§4.4](#44-servertime-and-clock-skew)).
7. **Check job age** against the local policy's `limits.max_job_age_seconds`.
8. **Check the local policy** for whatever the intent needs — and then hand off to the root helper,
   **which checks the policy again itself**. The agent-side check is an optimisation and a better
   error message; the helper's check is the one that is load-bearing, because it runs as root against
   the root-owned file and does not trust its caller.

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
`unsupported_intent`, `expired`.

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

| Status | Agent behaviour |
| --- | --- |
| `400` | Log and drop; do not retry an unparseable request |
| `401` | Certificate rejected or revoked. Stop calling; log loudly. Do **not** attempt re-enrolment automatically — a host that re-enrols itself on `401` is a host an attacker can re-enrol |
| `409` | Enrolment conflict; stop and require operator action |
| `413` | Body too large. Truncate further and retry once, then drop |
| `429` | Honour `Retry-After`, then full-jitter backoff |
| `5xx` | Full-jitter backoff, retry indefinitely |

Servers SHOULD return a problem body of `{"error":"code","message":"human text"}` but agents MUST NOT
require it, and MUST NOT parse `message` for control flow.

## 12. Versioning

The path segment `v1` changes only for a breaking change. Additive changes — new response fields, new
intents, new result fields — do not bump it, which is why both sides ignore unknown fields.

An agent that receives an intent it does not know reports `unsupported_intent`; the control plane uses
that, plus `agentVersion`, to decide what to schedule. Old agents are therefore safe to leave running:
they refuse what they do not understand rather than guessing.
