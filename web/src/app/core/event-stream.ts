import { Injectable, computed, inject, signal } from '@angular/core';

import { FleetEvent } from './api.models';
import { ApiService } from './api.service';
import { TokenStore } from './token-store';

/** How many events the in-memory feed keeps, which is what the bell and the inbox page read. */
const FEED_LIMIT = 200;

/** Where the browser-notification opt-in is remembered between page loads. */
const NOTIFY_KEY = 'farrier.desktopNotifications';

/** Where the id of the newest event the operator has seen is remembered. */
const SEEN_KEY = 'farrier.lastSeenEvent';

/**
 * How many toasts are on screen at once before the oldest is dropped.
 *
 * Small on purpose. A host that reboots badly can move a dozen units in one heartbeat, and a stack
 * that grew with the incident would cover the page an operator is trying to read during exactly that
 * incident. Nothing is lost by dropping one: the inbox is the durable copy and the bell still counts.
 */
const TOAST_LIMIT = 3;

/**
 * How long one toast stays before it expires by itself, in milliseconds.
 *
 * Long enough to read a summary and reach for the link, short enough that a notification nobody
 * acted on clears itself. A toast that waited for a dismissal would turn into a second, worse inbox
 * — one whose contents nobody can search and everybody eventually clicks away unread.
 */
const TOAST_MILLISECONDS = 10_000;

/**
 * The reconnect delays, in milliseconds, one per consecutive failure.
 *
 * Bounded and short at the start, because the commonest reason a stream drops is a control plane
 * being restarted and an operator staring at a stale page for thirty seconds concludes the feature is
 * broken. The last entry repeats for every further failure, so a control plane that is down for an
 * afternoon is polled twice a minute rather than continuously.
 */
const RECONNECT_DELAYS = [1_000, 2_000, 5_000, 15_000, 30_000];

/**
 * The live event feed: a connection to the control plane's stream, and what to do with what arrives.
 *
 * Three decisions are worth stating, because each has an obvious alternative that is wrong here.
 *
 * **`fetch` rather than `EventSource`.** `EventSource` cannot set a request header, and this API
 * authenticates with a bearer token. The usual workaround is a token in the query string, which puts
 * an operator's credential into every access log and proxy trace it passes. Reading the stream from a
 * `fetch` response body costs the reconnect logic below and keeps the credential in the one place it
 * belongs.
 *
 * **The stream is never the source of truth.** A dropped connection, a full buffer or a deploy loses
 * events, by design on the server side. So every connection begins by re-reading the durable inbox and
 * merging, and the feed de-duplicates on the event id. A missed event shows up on the next reconnect
 * rather than being lost.
 *
 * **A notification is never actionable.** There is no approve-from-toast and no retry-from-toast here
 * or anywhere downstream of it. Clicking a desktop notification focuses the tab and an in-app toast
 * carries at most a link to a page; everything that changes state goes through the admin API with its
 * normal authentication, and a destructive job still needs its offline signature and its second-person
 * release. The notification's whole job is to make somebody look.
 *
 * Delivery to an open tab is the toast below, not the desktop notification. The desktop one is
 * optional, off by default and needs a permission the browser will only be asked for once — so an
 * operator who declined it, or never found the switch, would otherwise get a silently incrementing
 * badge and nothing else, which is precisely the operator issue #4 is about.
 */
@Injectable({ providedIn: 'root' })
export class EventStream {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** Holds the operator's bearer token, and decides whether there is anything to connect with. */
  private readonly tokens = inject(TokenStore);

  /** The merged feed, newest first, bounded to FEED_LIMIT. */
  private readonly feed = signal<FleetEvent[]>([]);

  /** Whether a stream is currently connected, for the indicator beside the bell. */
  private readonly live = signal(false);

  /** The id of the newest event the operator has acknowledged, for the unread count. */
  private readonly lastSeen = signal(readStored(SEEN_KEY));

  /** Whether the operator asked for desktop notifications, independent of whether the browser agrees. */
  private readonly wanted = signal(readStored(NOTIFY_KEY) === 'yes');

  /** The events currently on screen as toasts, newest first. */
  private readonly toasted = signal<FleetEvent[]>([]);

  /**
   * The expiry timers, by event id.
   *
   * Held rather than fired and forgotten, so that a dismissal, the stack's cap or a sign-out can
   * cancel one. A timer that outlived its toast would remove whatever had taken its place.
   */
  private readonly toastTimers = new Map<string, ReturnType<typeof setTimeout>>();

  /** Aborts the in-flight stream when the token changes or the operator signs out. */
  private controller: AbortController | null = null;

  /** How many consecutive connection attempts have failed, which picks the reconnect delay. */
  private failures = 0;

  /** Set once start() has run, so a second call from a second component does not open a second stream. */
  private started = false;

  /**
   * Which connect loop is the current one.
   *
   * Incremented by every start() and stop(). A loop compares it on each pass and returns when it no
   * longer matches, which is what keeps sign-out-and-back-in from leaving two streams running: the
   * old loop is asleep in its backoff when the new one starts, and a bare `started` flag would be
   * true again by the time it woke.
   */
  private generation = 0;

  /** The events, newest first. */
  readonly events = this.feed.asReadonly();

  /** Whether the live stream is connected. A page can say "live" rather than implying it. */
  readonly connected = this.live.asReadonly();

  /** Whether the operator has asked for desktop notifications. */
  readonly desktopWanted = this.wanted.asReadonly();

  /**
   * The events to show as toasts, newest first.
   *
   * `FleetEvent[]` rather than a toast type of its own, and the absence is the design: a wrapper with
   * an `action` field, or a callback, is the first half of the approve-from-toast button issue #4
   * rules out. There is nothing here to hang one on, so adding one would have to be a deliberate
   * change to this type rather than a component quietly passing a handler in.
   */
  readonly toasts = this.toasted.asReadonly();

  /**
   * How many events have arrived since the operator last opened the inbox.
   *
   * Counted by position rather than by a per-event flag: the feed is ordered newest first, so
   * everything above the last acknowledged id is unread, and an event that arrives while the page is
   * closed is counted the moment the inbox is fetched.
   */
  readonly unread = computed(() => {
    const seen = this.lastSeen();
    if (!seen) {
      return this.feed().length;
    }
    const index = this.feed().findIndex((event) => event.id === seen);
    return index < 0 ? this.feed().length : index;
  });

  /**
   * Connects the stream and loads the inbox behind it.
   *
   * Idempotent, because the shell and the inbox page both want the feed and neither should have to
   * know whether the other got there first.
   */
  start(): void {
    if (this.started || !this.tokens.hasToken()) {
      return;
    }
    this.started = true;
    this.generation += 1;
    void this.connect(this.generation);
  }

  /** Disconnects and forgets everything, for sign-out. */
  stop(): void {
    this.started = false;
    this.generation += 1;
    this.failures = 0;
    this.controller?.abort();
    this.controller = null;
    this.live.set(false);
    this.feed.set([]);
    // The toasts go with the feed. They are this fleet's incidents rendered over whatever is on
    // screen, and leaving one up after a sign-out would put them in front of whoever signs in next.
    for (const handle of this.toastTimers.values()) {
      clearTimeout(handle);
    }
    this.toastTimers.clear();
    this.toasted.set([]);
  }

  /**
   * Takes one toast off the stack.
   *
   * Public because the dismiss control is on a component and the expiry timer is here, and both do
   * exactly this. It is also the only thing a toast can ask of this service, which is the whole of
   * what "a notification is never actionable" means in code.
   */
  dismissToast(id: string): void {
    this.clearToastTimer(id);
    this.toasted.update((held) => held.filter((event) => event.id !== id));
  }

  /** Marks everything currently in the feed as read. */
  markSeen(): void {
    const newest = this.feed()[0];
    if (!newest) {
      return;
    }
    this.lastSeen.set(newest.id);
    writeStored(SEEN_KEY, newest.id);
  }

  /**
   * Re-reads the durable inbox and merges it into the feed.
   *
   * Exposed because the inbox page calls it on open: the feed only holds what this tab has seen, and
   * an operator who has just signed in wants overnight's events rather than the last four minutes'.
   */
  refresh(): void {
    this.api.events().subscribe({
      next: (response) => this.merge(response.events),
      // Swallowed on purpose: this runs on every reconnect, and a page that popped an error card each
      // time a control plane restarted would be a page whose errors nobody reads. The inbox page
      // fetches for itself and shows its own failures.
      error: () => undefined,
    });
  }

  /**
   * Asks the browser for permission to show desktop notifications, and remembers the answer.
   *
   * Requested on a click and never on load, because a permission prompt that appears unprompted is
   * the one every operator denies — after which the browser will not ask again and the feature is
   * gone for that origin.
   */
  async enableDesktop(): Promise<void> {
    if (!supportsDesktopNotifications()) {
      return;
    }
    const permission =
      Notification.permission === 'granted' ? 'granted' : await Notification.requestPermission();
    const granted = permission === 'granted';
    this.wanted.set(granted);
    writeStored(NOTIFY_KEY, granted ? 'yes' : 'no');
  }

  /** Stops showing desktop notifications, without touching the browser's own permission. */
  disableDesktop(): void {
    this.wanted.set(false);
    writeStored(NOTIFY_KEY, 'no');
  }

  /** Reports whether this browser can show desktop notifications at all. */
  desktopAvailable(): boolean {
    return supportsDesktopNotifications();
  }

  /** Reports the browser's own permission state, for a page that needs to explain a denial. */
  desktopPermission(): NotificationPermission | 'unsupported' {
    return supportsDesktopNotifications() ? Notification.permission : 'unsupported';
  }

  /**
   * Holds one connection open, then reconnects, until stop() or a lost token.
   *
   * The loop is the reconnect policy: `EventSource` would have supplied one, and this is what
   * replaces it.
   *
   * The inbox is re-read *after* the stream says it is registered, and the order is the whole
   * correctness of the reconciliation. Reading first — or, worse, reading concurrently — leaves a
   * window: an event emitted after the inbox query ran and before the subscription existed is in
   * neither answer, and because a healthy stream then stays open for hours, it would not surface
   * until the next reconnect. Registering first makes the window close in the other direction, where
   * the overlap is a duplicate the feed's de-duplication already absorbs.
   */
  private async connect(generation: number): Promise<void> {
    while (this.started && this.generation === generation && this.tokens.hasToken()) {
      const clean = await this.readStream(() => this.refresh());
      if (!this.started || this.generation !== generation) {
        return;
      }
      this.failures = clean ? 0 : this.failures + 1;
      const delay = RECONNECT_DELAYS[Math.min(this.failures, RECONNECT_DELAYS.length - 1)];
      await sleep(delay);
    }
  }

  /**
   * Reads one connection to exhaustion and returns whether it was established at all.
   *
   * The return value feeds the backoff and only that: a stream that connected and later dropped is a
   * restart worth retrying immediately, and one that never connected is a control plane that is down
   * or a token that is wrong, which is worth backing off from.
   *
   * `onRegistered` fires once the server has confirmed the subscription, which is what the inbox
   * reconciliation waits for. A response with headers is not that confirmation — the handler could
   * in principle write them before subscribing — so the signal is the greeting frame, which the
   * handler writes only after it has registered.
   */
  private async readStream(onRegistered: () => void): Promise<boolean> {
    const controller = new AbortController();
    this.controller = controller;
    let connected = false;

    try {
      const response = await fetch('/api/v1/events/stream', {
        headers: { Authorization: `Bearer ${this.tokens.token()}` },
        signal: controller.signal,
        // The stream is a credentialed read of control-plane state; a shared cache holding one would
        // be one customer's incidents replayed to whoever asked next. The server says no-store too.
        cache: 'no-store',
      });
      if (!response.ok || !response.body) {
        return false;
      }
      connected = true;
      this.live.set(true);
      await this.consume(response.body, onRegistered);
    } catch {
      // Aborts and network failures land here alike, and neither is worth surfacing: the loop above
      // reconnects, and the indicator beside the bell already says the stream is not live.
    } finally {
      this.live.set(false);
      if (this.controller === controller) {
        this.controller = null;
      }
    }
    return connected;
  }

  /**
   * Decodes the server-sent-events framing and hands each event to the feed.
   *
   * A minimal parser rather than a library: the server sends only comment lines for its heartbeat and
   * `data:` lines carrying one JSON object each, so the whole grammar this needs is "split on a blank
   * line, take the data lines". Anything the server adds later that this does not understand is
   * ignored, which is the same rule the protocol states for every other direction.
   */
  private async consume(
    body: ReadableStream<Uint8Array>,
    onRegistered: () => void,
  ): Promise<void> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let registered = false;

    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        return;
      }
      buffer += decoder.decode(value, { stream: true });

      let boundary = buffer.indexOf('\n\n');
      while (boundary >= 0) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        if (!registered) {
          // Any complete frame proves the subscription exists, because the handler writes its
          // greeting only after registering. Keyed on the first frame rather than on the greeting's
          // text so that a server which one day drops the greeting still reconciles.
          registered = true;
          onRegistered();
        }
        this.handleFrame(frame);
        boundary = buffer.indexOf('\n\n');
      }
    }
  }

  /** Turns one SSE frame into an event, ignoring the heartbeat comments and anything unparseable. */
  private handleFrame(frame: string): void {
    for (const line of frame.split('\n')) {
      if (!line.startsWith('data:')) {
        continue;
      }
      try {
        const event = JSON.parse(line.slice(5).trim()) as FleetEvent;
        if (event.id) {
          this.merge([event]);
          this.announce(event);
        }
      } catch {
        // A frame this build cannot parse is a frame from a newer server. Ignored rather than
        // logged: the durable inbox has it, and a console full of parse errors during an upgrade
        // helps nobody.
      }
    }
  }

  /**
   * Merges events into the feed, newest first, de-duplicated on id.
   *
   * De-duplication is what makes the stream and the inbox safe to combine: the same event arrives
   * from both, and an operator counting incidents must not count it twice.
   */
  private merge(incoming: FleetEvent[]): void {
    if (incoming.length === 0) {
      return;
    }
    this.feed.update((held) => mergeEvents(held, incoming).slice(0, FEED_LIMIT));
  }

  /**
   * Announces one event that arrived live: a toast, and a desktop notification where one is wanted.
   *
   * Called only from the stream's frame handler and never from `merge`, and the difference matters.
   * Merging happens on every reconnect, when the durable inbox is re-read in full; toasting from
   * there would fill the screen with overnight's events every time a control plane restarted, which
   * is how an operator learns to ignore the corner of the page these appear in.
   */
  private announce(event: FleetEvent): void {
    this.raise(event);
    this.notifyDesktop(event);
  }

  /**
   * Puts one event on the toast stack, capped and self-expiring.
   *
   * Every kind, without an editorial filter. The vocabulary is closed and small, and a component
   * that decided which kinds were worth interrupting somebody for would be a second alerting policy
   * beside the one on the alerts page — undocumented, unconfigurable, and disagreeing with it.
   */
  private raise(event: FleetEvent): void {
    if (this.toastTimers.has(event.id)) {
      // Already on screen. The same event reaches this from a re-delivering stream and from a
      // reconnect overlapping a live frame, and one incident must not stack twice.
      return;
    }
    this.toastTimers.set(
      event.id,
      setTimeout(() => this.dismissToast(event.id), TOAST_MILLISECONDS),
    );
    const stacked = [event, ...this.toasted()];
    for (const dropped of stacked.slice(TOAST_LIMIT)) {
      this.clearToastTimer(dropped.id);
    }
    this.toasted.set(stacked.slice(0, TOAST_LIMIT));
  }

  /** Cancels one toast's expiry timer, so nothing fires against an id that is no longer on screen. */
  private clearToastTimer(id: string): void {
    const handle = this.toastTimers.get(id);
    if (handle !== undefined) {
      clearTimeout(handle);
      this.toastTimers.delete(id);
    }
  }

  /**
   * Shows one desktop notification, when the operator asked for them and the browser agreed.
   *
   * Tagged with the event id so that a browser which re-delivers, or a second tab of the same
   * console, replaces the notification rather than stacking a second copy of it.
   */
  private notifyDesktop(event: FleetEvent): void {
    if (!this.wanted() || !supportsDesktopNotifications() || Notification.permission !== 'granted') {
      return;
    }
    try {
      const notification = new Notification(event.hostname || 'Farrier', {
        body: event.summary,
        tag: event.id,
      });
      // Focusing the tab is the whole interaction. A notification is a read of control-plane state
      // and never a control: anything that would start or release a job belongs on a page behind the
      // admin API's authentication, not behind a click on a system toast.
      notification.onclick = () => window.focus();
    } catch {
      // Some browsers refuse to construct one outside a service worker even with permission granted.
      // The event is in the feed either way, which is the delivery that was promised.
    }
  }
}

/**
 * Merges event lists into one, newest first and de-duplicated on the event id.
 *
 * Exported because the feed is not the only place two sources of the same events meet: the events
 * page merges a server-filtered inbox with the live stream's matching events, and an operator
 * counting incidents must not count one twice because it arrived from both. Later sources win on a
 * duplicate, which is what lets a fresh fetch correct a field a streamed copy carried.
 */
export function mergeEvents(...sources: FleetEvent[][]): FleetEvent[] {
  const byId = new Map<string, FleetEvent>();
  for (const source of sources) {
    for (const event of source) {
      byId.set(event.id, event);
    }
  }
  return [...byId.values()].sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
}

/** Reports whether this browser exposes the Notification API at all. */
function supportsDesktopNotifications(): boolean {
  return typeof Notification !== 'undefined';
}

/** Reads a remembered value, tolerating a storage API that refuses to answer. */
function readStored(key: string): string {
  try {
    return localStorage.getItem(key) ?? '';
  } catch {
    return '';
  }
}

/** Remembers a value, tolerating a storage API that refuses to answer. */
function writeStored(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Private browsing refuses storage. Losing the opt-in across reloads is a smaller problem than a
    // page that will not render.
  }
}

/** Resolves after a delay, so the reconnect loop can read as a loop. */
function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
