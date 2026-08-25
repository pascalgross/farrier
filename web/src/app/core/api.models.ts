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

  /**
   * Every systemd unit the host reported, with its load, active and sub state.
   *
   * The full list rather than only the failed ones, because the distinction between `failed`,
   * `inactive` and `not-found` is the point: a masked unit and a crashed unit are different problems.
   */
  services?: UnitState[];

  /**
   * Whether that list was cut at the protocol's cap, in sorted order.
   *
   * Reported so that "no failed units" and "the failed unit sorts after the cap" do not render
   * identically — the same rule `serviceScanComplete` follows, and for the same reason.
   */
  servicesTruncated?: boolean;

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

    /**
     * Units whose state changes this host considers worth an event, matched the same way.
     *
     * Empty means every unit, which is the opposite default from `restartable` and deliberately so:
     * a fresh host should surface a failed unit rather than hide it behind a setting nobody has
     * heard of, and permitting an action is a different question from reporting a fact.
     */
    watched?: string[];
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

/** The body of `POST /api/v1/session`. */
export interface SignInRequest {
  /** The address the operator signs in with, matched without regard to case or surrounding space. */
  email: string;

  /** What they typed. It is sent once, over TLS, and is never stored by this application. */
  password: string;
}

/**
 * The response of `POST /api/v1/session`.
 *
 * There is deliberately no token in it. The credential is an HttpOnly cookie the browser keeps and
 * this application cannot read, which is the point of signing in this way rather than pasting a bearer
 * token into `localStorage`. What comes back is who signed in, so the shell can render a name without
 * a second round trip.
 */
export interface SignedIn {
  /** The identifier the provider knows this operator by, which for an account is their address. */
  subject: string;

  /** A human-readable name. */
  display: string;

  /** Which provider authenticated them. */
  provider: string;

  /** The provider-qualified string recorded as the author of anything they do. */
  principal: string;
}

/**
 * One event as the inbox and the live stream render it.
 *
 * The same shape from both sources on purpose: a page that reconciles a live stream against the
 * durable inbox must not have to translate between two spellings of the same event.
 */
export interface FleetEvent {
  /** The event identifier, which is what de-duplicates a streamed event against a fetched one. */
  id: string;

  /** A member of the control plane's closed vocabulary, such as `service.failed`. */
  kind: string;

  /** The host it concerns, absent for fleet-wide events such as a digest. */
  hostId?: string;

  /** The hostname, carried for display because an opaque identifier helps nobody. */
  hostname?: string;

  /** One line of human-readable text. */
  summary: string;

  /** When it happened, by the control plane's clock. */
  at: string;

  /** Event-specific fields, rendered only where a page knows what to do with them. */
  detail?: Record<string, unknown>;
}

/** The response of `GET /api/v1/events`. */
export interface EventsResponse {
  /** The inbox, newest first. */
  events: FleetEvent[];

  /** The control plane's clock, so ages are rendered against it rather than the browser's. */
  serverTime: string;
}

/** One systemd unit as a host reported it. */
export interface UnitState {
  /** The unit name, such as `nginx.service`. */
  name: string;

  /** Whether the unit is loaded, masked or absent. A masked unit is a different problem from a crash. */
  loadState: string;

  /** The active state, which is what `failed` is read from. */
  activeState: string;

  /** The finer-grained state, carried for display. */
  subState: string;
}

/** One host's failed units, as the fleet-wide service view renders them. */
export interface FailedServiceHost {
  /** The host. */
  hostId: string;

  /** What it calls itself. */
  hostname: string;

  /** Whether it has been heard from recently. */
  online: boolean;

  /** Its units in the failed state, each carrying the load state that says what kind of failure. */
  failed: UnitState[];

  /**
   * Whether this host's unit list was cut at the protocol's cap.
   *
   * Rendered rather than swallowed: "no failed units here" and "the failed unit sorts after the cap"
   * must not look the same, which is the same rule the needrestart scan already follows.
   */
  servicesTruncated: boolean;

  /**
   * Whether the control plane could read this host's facts at all.
   *
   * True for a host that has never reported, or whose stored facts will not parse. It is a third
   * answer beside "clean" and "failing" and has to render as one: a host nothing is known about is
   * not a host with no failed units, which is the same distinction `servicesTruncated` exists to
   * make one level down.
   */
  factsUnknown: boolean;
}

/** The response of `GET /api/v1/services/failed`. */
export interface FailedServicesResponse {
  /** Only the hosts with something failed, with a truncated list, or with no readable facts. */
  hosts: FailedServiceHost[];

  /**
   * How many hosts were examined, so "3 of 300" is renderable.
   *
   * Revoked hosts are not in it. They are not part of the fleet this page is about, and counting
   * them made the denominator include machines somebody had deliberately removed.
   */
  total: number;

  /** The control plane's clock. */
  serverTime: string;
}

/** One recorded change of a unit's active state. */
export interface UnitTransition {
  /** The unit that changed. */
  unit: string;

  /** The state it was in. */
  from: string;

  /** The state it moved to. */
  to: string;

  /** When the control plane observed the change. */
  at: string;
}

/** The response of `GET /api/v1/hosts/{id}/services/history`. */
export interface ServiceHistoryResponse {
  /** The transitions, newest first. */
  transitions: UnitTransition[];

  /**
   * The heartbeat interval, which is this history's resolution.
   *
   * Stated by the server rather than assumed by the page: a unit that failed and recovered between
   * two beats is not in here, and an operator reading the history during an incident needs to know
   * that before they conclude nothing happened.
   */
  resolutionSeconds: number;

  /** The control plane's clock. */
  serverTime: string;
}

/** One alerting rule as the control plane holds it. */
export interface AlertRule {
  /** The rule identifier. */
  id: string;

  /** What it watches: `host_silent`, `security_updates`, `reboot_required`, `unit_failed`, `job_failed`. */
  condition: string;

  /** Parameterises the condition: minutes silent, pending updates, or days a reboot has been due. */
  threshold: number;

  /** How long before one firing pair may notify again, zero for the server's default. */
  cooldownSeconds: number;

  /** Who gets mailed. Everything else — the inbox, the stream, the webhook — happens regardless. */
  emailTo: string[];

  /** Whether the rule is live. */
  enabled: boolean;

  /** When it was created. */
  createdAt: string;

  /** Which operator created it. */
  createdBy: string;

  /** When it last tried to mail somebody, absent for never. */
  lastDeliveryAt?: string;

  /**
   * Why that attempt failed, absent when it succeeded.
   *
   * Shown on the rule rather than left in a server log, because an alert that never went out and an
   * alert that never fired are indistinguishable from an inbox.
   */
  lastDeliveryError?: string;
}

/** The response of `GET /api/v1/alerts`. */
export interface AlertRulesResponse {
  /** The rules, oldest first. */
  rules: AlertRule[];

  /** What a zero cooldown means, reported so the page does not hard-code the server's number. */
  defaultCooldownSeconds: number;

  /**
   * Whether this control plane has a mail relay at all.
   *
   * Rendered as a warning beside any rule with recipients when it is false: adding an address to a
   * rule on an installation that was never given `--smtp-host` is the commonest version of the
   * mistake, and it fails silently everywhere except here.
   */
  mailConfigured: boolean;
}

/** The body of `POST /api/v1/alerts` and `PATCH /api/v1/alerts/{id}`. */
export interface AlertRuleRequest {
  /** What to watch. Required on create and refused on update: a rule's condition is its identity. */
  condition?: string;

  /** Parameterises the condition. */
  threshold: number;

  /** Re-notification bound in seconds, zero for the server's default. */
  cooldownSeconds: number;

  /** Mail recipients, empty for none. */
  emailTo: string[];

  /** Whether the rule is live. */
  enabled?: boolean;
}

/** One provisioning template, as the list renders it. */
export interface TemplateSummary {
  /** The template's name, which is what an enrolment token names to request it. */
  name: string;

  /** The highest version stored. Every save is a new version; there is no update path. */
  latestVersion: number;

  /** When the latest version was stored. */
  createdAt: string;

  /** Which operator stored it. */
  createdBy: string;

  /**
   * Whether the latest version carries an offline signature.
   *
   * An unsigned template can be rendered and pasted into a provisioner; only a signed one may be
   * handed to an enrolling agent, because the agent verifies it against its own trusted-signers and
   * this control plane cannot produce that signature.
   */
  signed: boolean;
}

/** The response of `GET /api/v1/templates`. */
export interface TemplatesResponse {
  /** One summary per template, newest first. */
  templates: TemplateSummary[];
}

/** One immutable version of a template, body included. */
export interface TemplateVersion {
  /** The template's name. */
  name: string;

  /** This version's number. */
  version: number;

  /** The cloud-config body, verbatim. */
  body: string;

  /** Whether an offline signature is attached. */
  signed: boolean;

  /** The key that signed it, absent for an unsigned version. */
  signerKeyId?: string;

  /** When it was stored. */
  createdAt: string;

  /** Which operator stored it. */
  createdBy: string;

  /** The placeholder names the body substitutes, so a render form can be built without parsing it. */
  placeholders: string[];

  /**
   * Secret shapes found in the body, with the consequence spelled out.
   *
   * Warnings and never refusals: user-data is readable from inside the instance and from the metadata
   * service, so a secret in a template is a secret in plaintext on every host it provisions — and a
   * control that blocked the save would only teach operators to route around it.
   */
  warnings: string[];
}

/**
 * What a save answers with.
 *
 * Narrower than `TemplateVersion` on purpose, and the narrowness is the server's rather than this
 * file's: the create response confirms what was stored and deliberately does not echo the body back,
 * because a body is where operators put the things the warnings are about. A client that wants the
 * whole version reads it, which is also the only way to be sure it is looking at what was stored
 * rather than at what it sent.
 */
export interface StoredTemplateVersion {
  /** The template's name. */
  name: string;

  /** The version just written. */
  version: number;

  /** Whether it carries an offline signature. */
  signed: boolean;

  /** The placeholder names the body substitutes. */
  placeholders: string[];

  /** Secret shapes found in the body, with the consequence spelled out. */
  warnings: string[];
}

/**
 * One stored revision as the version listing renders it, without its body.
 *
 * No body, because the listing is about the shape of a template's history rather than its contents:
 * bodies are sealed, potentially large, and the one a caller actually wants is fetched by naming its
 * version — which is also the request that is marked non-cacheable, because that is the one carrying
 * something worth keeping out of a cache.
 */
export interface TemplateRevision {
  /** This revision's number. */
  version: number;

  /** Whether it carries an offline signature, and so may be issued to an enrolling host. */
  signed: boolean;

  /** The key that signed it, absent for an unsigned revision. */
  signerKeyId?: string;

  /** When it was stored. */
  createdAt: string;

  /** Which operator stored it. */
  createdBy: string;
}

/** The response of `GET /api/v1/templates/{name}/versions`. */
export interface TemplateVersionsResponse {
  /** The template these revisions belong to. */
  name: string;

  /** Every stored revision, newest first. */
  versions: TemplateRevision[];
}

/** The body of `POST /api/v1/templates`. */
export interface CreateTemplateRequest {
  /** The template's name; an existing name stores the next version of it. */
  name: string;

  /** The cloud-config body. */
  body: string;

  /** A detached signature made offline by `farrier sign-template`, absent for an unsigned version. */
  signature?: string;

  /** The signing key's identity, required with a signature. */
  signerKeyId?: string;

  /** The signature algorithm, required with a signature. */
  signerAlgorithm?: string;
}

/** The body of `POST /api/v1/templates/{name}/render`. */
export interface RenderTemplateRequest {
  /** Which version to render, omitted for the latest. */
  version?: number;

  /** The values substituted into the template's placeholders. */
  params: Record<string, string>;

  /** How to configure the enrolment token, when the body substitutes one. */
  token?: {
    /** A human-readable name for the token, defaulted to naming the template. */
    label?: string;
    /** The fleet group hosts enrolled with it join. */
    group?: string;
    /** The token's lifetime, defaulted to the server's. */
    ttlSeconds?: number;
    /** The template this token may request at enrolment, which is how a Tier 2 bootstrap is armed. */
    bootstrap?: string;
  };
}

/**
 * The response of a render.
 *
 * It is a credential and is treated as one: nothing stores it, it is not cacheable, and an operator
 * who loses it renders again — which mints a fresh token and costs nothing.
 */
export interface RenderedTemplate {
  /** The template rendered. */
  name: string;

  /** The version rendered. */
  version: number;

  /** The user-data, ready to paste into a provisioner. */
  userData: string;

  /** Secret shapes found in the *rendered* output, which includes what substitution introduced. */
  warnings: string[];

  /** When the minted enrolment token expires, absent when the template mints none. */
  tokenExpiresAt?: string | null;

  /** The control plane's own sentence about the output being shown once. */
  note: string;
}
