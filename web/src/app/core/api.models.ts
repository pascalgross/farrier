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
