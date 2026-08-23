/**
 * Types mirroring the Farrier control plane's administrative API.
 *
 * They are written by hand rather than generated, because there are few of them and because the shapes
 * are stable by design: `docs/PROTOCOL.md` says additive changes do not bump the version and unknown
 * fields are ignored in both directions, so a hand-written interface that is a subset of what the
 * server sends stays correct as the server grows.
 */

/** One trusted signing key as a host reports it, for display in the audit trail. */
export interface SignerSummary {
  /** The identity from the host's own `trusted-signers` file, recorded against every signed job. */
  keyId: string;

  /** The signature algorithm, `ed25519` or `ecdsa-p256`. */
  algorithm: string;

  /**
   * How the private key is held, as the administrator annotated it.
   *
   * It is advisory: nothing can verify where a signature was produced. It exists so that
   * `ops-laptop (file)` reads differently from `ops-yubikey-1 (pkcs11)` to whoever reviews the log.
   */
  backend?: string;
}

/** The parts of a host's fact report the fleet list renders. */
export interface HostFacts {
  /** What the host calls itself. */
  hostname?: string;

  /** Distribution identity, used to show the release and whether Farrier supports it. */
  distribution?: {
    /** The os-release ID, `ubuntu` or `debian`. */
    id: string;
    /** The release codename, such as `noble`. */
    codename: string;
    /** The release version, such as `24.04`. */
    version: string;
    /** The os-release PRETTY_NAME. */
    prettyName?: string;
    /** Whether this release is one Farrier supports. */
    supported?: boolean;
  };

  /** The running kernel release. */
  kernel?: string;

  /** Pending update counts, with security separated from the rest. */
  packages?: {
    /** How many pending updates come from a security origin. */
    upgradableSecurity: number;
    /** How many updates are pending in total. */
    upgradableTotal: number;
  };

  /** Whether a reboot is needed and what still runs replaced libraries. */
  reboot?: {
    /** Whether a reboot is required. */
    required: boolean;
    /** The packages that require it. */
    reasons?: string[];
    /** Units that still hold replaced libraries, per needrestart. */
    services?: string[];
    /**
     * Whether the needrestart scan could see every process.
     *
     * The agent is unprivileged, so it often cannot. An incomplete scan is shown as incomplete rather
     * than as a clean bill of health: "no services need restarting" and "I could not see the services
     * that do" must not look the same.
     */
    serviceScanComplete?: boolean;
  };

  /** Ubuntu Pro state, or a not-applicable marker on Debian. */
  subscription?: {
    /**
     * Whether the concept exists on this host at all.
     *
     * False on Debian, where it must render as "not applicable" rather than "unknown". A Debian host
     * with a permanent amber ESM badge teaches its operator to ignore the dashboard.
     */
    applicable: boolean;
    /** Whether the host is attached to a subscription. */
    attached: boolean;
    /** Each Ubuntu Pro service and its status. */
    services?: Record<string, string>;
    /** An explanation of an absent or unreadable answer. */
    note?: string;
  };
}

/** One host as the fleet list and the host detail page render it. */
export interface Host {
  /** The control plane's identifier for the host, and its certificate subject. */
  id: string;

  /** What the host calls itself. Display only: hostnames are not unique and a host can change its own. */
  hostname: string;

  /** The fleet group, from the enrolment token. */
  group: string;

  /** The agent build the host last reported. */
  agentVersion: string;

  /** When the host first enrolled. */
  enrolledAt: string;

  /** The last heartbeat, or null if the host has never been heard from. */
  lastSeen: string | null;

  /** Whether the host has been heard from recently enough to be considered up. */
  online: boolean;

  /** How long the host has been up, in seconds. */
  uptimeSeconds: number;

  /** The host's own measurement of its offset from the control plane, in seconds. */
  clockOffsetSeconds: number;

  /** Whether the offset is large enough that the host refuses privileged intents. */
  clockSkewed: boolean;

  /**
   * Whether `/etc/farrier/paused` exists on the host.
   *
   * It is a local kill switch the control plane cannot override, and there is deliberately no
   * `agent.resume` intent — so this is shown as a state, never as something to toggle from here.
   */
  paused: boolean;

  /** Whether this host's certificates have been withdrawn. */
  revoked: boolean;

  /** The digest of the facts document the host last reported. */
  factsDigest: string;

  /** The digest of the effective local policy the host last reported. */
  policyDigest: string;

  /** The digest of the host's trusted key set. */
  signersDigest: string;

  /** The last full inventory, or null if none has been received. */
  facts: HostFacts | null;

  /** The host's last reported effective policy, or null. */
  policy: HostPolicy | null;

  /** The host's trusted key identities, or null. */
  signers: SignerSummary[] | null;
}

/** A host's effective local policy, as it reports it. */
export interface HostPolicy {
  /** The `[updates]` section. */
  updates: {
    /** How far the host will go in applying updates: `none`, `security` or `all`. */
    allow: string;
    /** Whether the host applies permitted updates on its own timer. */
    autoApply: boolean;
    /** The maintenance window, or `always`. */
    window: string;
    /** The IANA timezone the window is expressed in. */
    timezone: string;
    /** Whether and when the host will reboot: `never` or `window`. */
    reboot: string;
  };

  /** The `[services]` section. */
  services: {
    /** Units the host will act on, matched as shell globs. Empty means none. */
    restartable: string[];
  };

  /** The `[limits]` section. */
  limits: {
    /** How long after issue a job may still be executed. */
    maxJobAgeSeconds: number;
  };

  /** Where the policy was read from, for the UI to show when it is not the packaged file. */
  source: string;
}

/** The response of `GET /api/v1/hosts`. */
export interface FleetResponse {
  /** Every enrolled host, ordered by hostname. */
  hosts: Host[];

  /** The heartbeat pacing the control plane is handing out, used to explain what "online" means. */
  heartbeatSeconds: number;

  /** The control plane's clock, so the UI can render ages without trusting the browser's. */
  serverTime: string;
}

/** One member of the intent catalogue. */
export interface CatalogueEntry {
  /** The wire identifier, such as `services.list`. */
  name: string;

  /** The authorisation tier: `read`, `routine` or `destructive`. */
  class: string;

  /** One line of description. */
  summary: string;

  /** Whether an executor exists behind it on the agent. */
  implemented: boolean;

  /** Whether a key from the host's own `trusted-signers` is required. */
  requiresOfflineSignature: boolean;
}

/** The response of `GET /api/v1/catalogue`. */
export interface CatalogueResponse {
  /** Every operation this control plane can ask a host to perform. */
  intents: CatalogueEntry[];

  /** Operations this project has permanently refused to implement. */
  refused: string[];

  /** The control plane's own note about the set being closed. */
  note: string;
}

/** What a host reported back about a job it ran. */
export interface JobResult {
  /** The job this result belongs to. */
  jobId: string;

  /** One of the protocol's stable status strings, such as `succeeded` or `refused_by_policy`. */
  status: string;

  /** When the host started the operation, by the host's own clock. */
  startedAt: string;

  /** When it finished, by the same clock. Never the control plane's; see `docs/SECURITY.md` §4.3. */
  finishedAt: string;

  /** The root helper's exit status, where one applies. */
  exitCode: number;

  /** The last 64 KiB of what the operation printed. The tail, because the failure is at the end. */
  output?: string;

  /** Whether the output was cut, so a reader knows it is partial by design. */
  outputTruncated?: boolean;

  /** The intent-specific typed result, for the read intents that produce one. */
  result?: unknown;

  /** A human-readable failure or refusal reason, absent on success. */
  error?: string;
}

/** One job as the control plane holds it. */
export interface Job {
  /** The job identifier. For a signed job it is covered by the signature. */
  id: string;

  /** The host it was issued to. */
  hostId: string;

  /** The catalogue member. */
  intent: string;

  /** The parameter object, as validated by the catalogue's own decoder. */
  params: Record<string, unknown>;

  /** The authorisation tier, for display. The agent takes it from its own catalogue, not from here. */
  class: string;

  /** When the control plane created it. */
  createdAt: string;

  /** Which operator asked, recorded for the audit trail rather than for any decision. */
  createdBy: string;

  /** When the job becomes valid, checked on the host against the host's own clock. */
  notBefore: string;

  /** When it stops being valid, checked against the same clock and never a server-supplied one. */
  notAfter: string;

  /**
   * Whether an offline signature is attached.
   *
   * The signature itself is never sent to the browser. It authorises nothing here — the host is what
   * verifies it — and putting one on a dashboard would invite somebody to copy it.
   */
  signed: boolean;

  /** The key that signed it, absent for an unsigned job. */
  signerKeyId?: string;

  /** Whether somebody must release it before any host may claim it. */
  approvalRequired: boolean;

  /**
   * Whether the release must come from somebody other than the job's creator.
   *
   * Recorded on the job when it was created, from the fleet's approval mode at that moment — so a
   * fleet that has since changed its mind does not change what this job requires.
   */
  approvalDistinctOperator: boolean;

  /** When it was released, null until it is. */
  approvedAt: string | null;

  /** Which operator agreed, absent until one does. */
  approvedBy?: string;

  /** When a host took it, null if none has. */
  claimedAt: string | null;

  /** One word for what is happening: `queued`, `awaiting_approval`, `running`, or a result status. */
  state: string;

  /**
   * What the host reported, null until it does.
   *
   * Null rather than an empty object: "not reported yet" and "reported nothing" are different states,
   * and a host part way through a forty-minute upgrade is in the first one.
   */
  result: JobResult | null;
}

/** The response of `GET /api/v1/jobs`. */
export interface JobsResponse {
  /** Jobs, newest first. */
  jobs: Job[];

  /** The bound that was applied to this listing. */
  limit: number;

  /** The largest bound the control plane will accept. */
  maxLimit: number;

  /**
   * Whether the listing filled its bound, so there may be older jobs it did not return.
   *
   * It is reported by the server rather than worked out from the row count, because a client that has
   * to derive it is a client that will eventually forget to.
   */
  truncated: boolean;

  /**
   * The control plane's clock, so job ages can be rendered without trusting the browser's.
   *
   * The rule is the one `formatAge` states: everything on these pages measures against the server's
   * clock, because an age here is a decision input — "asked 4h ago" is why a second operator releases
   * a job — and a laptop ten minutes slow would understate every one of them.
   */
  serverTime: string;
}

/** The body of `POST /api/v1/jobs` for an unsigned, read-only job. */
export interface CreateReadJobRequest {
  /** The host to issue to. */
  hostId: string;

  /** The catalogue member, which must be a read intent for a request this shape. */
  intent: string;

  /** The parameter object. Every read intent takes an empty one. */
  params: Record<string, unknown>;
}

/** One tenant: an isolated fleet with its own hosts, operators and settings. */
export interface Tenant {
  /** The identifier every scoped row carries. */
  id: string;

  /** The short stable handle used in URLs, logs and support tickets. */
  slug: string;

  /** What the fleet is called in the interface. */
  displayName: string;

  /** When the tenant was created. */
  createdAt: string;

  /** How this fleet releases a destructive job: "none", "self" or "second_person". */
  approvalMode: string;

  /** Where this fleet's events are posted, empty for nowhere. */
  webhookUrl: string;
}

/**
 * The body of `GET /api/v1/whoami`.
 *
 * The application asks for it on start, for the same reason a shell prompt shows the hostname: an
 * operator with two fleets open in two tabs needs the page to say which one they are looking at before
 * they queue a reboot in it.
 */
export interface Whoami {
  /** The identifier the identity provider knows this operator by. */
  subject: string;

  /** A human-readable name. */
  display: string;

  /** Which provider authenticated them. */
  provider: string;

  /** The provider-qualified string recorded as the author of anything they do. */
  principal: string;

  /** The fleet this credential acts in. */
  tenant: Tenant;
}
