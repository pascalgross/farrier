import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';

import { ApiService } from './api.service';
import { EventStream, mergeEvents } from './event-stream';
import { EventsResponse, FleetEvent } from './api.models';
import { TokenStore } from './token-store';

/** A live stream this spec can push frames into, standing in for the control plane's. */
interface FakeStream {
  /** The response the feed's `fetch` is answered with. */
  response: Response;

  /** Writes one server-sent-events frame into it. */
  push: (frame: string) => void;

  /** Ends it, as a control plane being restarted would. */
  close: () => void;
}

/** Opens a fake event stream, so the toast path can be driven the way the server drives it. */
function fakeEventStream(): FakeStream {
  const encoder = new TextEncoder();
  let sink!: ReadableStreamDefaultController<Uint8Array>;
  const body = new ReadableStream<Uint8Array>({
    start: (controller) => {
      sink = controller;
    },
  });
  return {
    response: new Response(body, { status: 200 }),
    push: (frame: string) => sink.enqueue(encoder.encode(frame)),
    close: () => {
      try {
        sink.close();
      } catch {
        // Already closed or aborted by the feed. Nothing to tidy in that case, and a spec that
        // failed while cleaning up would hide the failure it was reporting.
      }
    },
  };
}

/** Builds one event as the control plane emits it. */
function event(id: string): FleetEvent {
  return {
    id,
    kind: 'service.failed',
    hostId: 'h-1',
    hostname: 'web-1',
    summary: `web-1: nginx.service failed (${id})`,
    at: '2026-08-22T12:00:00Z',
  };
}

/**
 * Waits for a state the stream reaches asynchronously.
 *
 * Polling rather than a fixed delay: the path from an enqueued frame to a signal runs through a
 * reader, a decoder and a promise chain, and a spec that guessed how long that takes is a spec that
 * fails on a loaded machine rather than when the code is wrong.
 */
async function until(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    if (predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('the feed never reached the state this spec was waiting for');
}

describe('EventStream toasts', () => {
  /** The feed under test. */
  let stream: EventStream;

  /** The connection it is reading. */
  let live: FakeStream;

  /** What the durable inbox answers with, which must never become a toast. */
  const inbox: EventsResponse = {
    events: [event('inbox-1')],
    serverTime: '2026-08-22T12:00:00Z',
  };

  beforeEach(() => {
    live = fakeEventStream();
    spyOn(window, 'fetch').and.returnValue(Promise.resolve(live.response));
    TestBed.configureTestingModule({
      providers: [
        { provide: ApiService, useValue: { events: () => of(inbox) } as unknown as ApiService },
        {
          provide: TokenStore,
          useValue: { token: () => 'token', hasToken: () => true } as unknown as TokenStore,
        },
      ],
    });
    stream = TestBed.inject(EventStream);
  });

  afterEach(() => {
    stream.stop();
    live.close();
  });

  /**
   * The defect issue #4 describes: an operator with the dashboard open in a tab got a silently
   * incrementing badge, because the only thing that announced an event was a desktop notification
   * that is off by default and needs a permission the browser asks for once.
   */
  it('raises a toast for an event that arrives on the live stream', async () => {
    stream.start();
    live.push(': connected\n\n');
    live.push(`data: ${JSON.stringify(event('e-1'))}\n\n`);

    await until(() => stream.toasts().length === 1);
    expect(stream.toasts()[0].id).toBe('e-1');
  });

  /**
   * The inbox is re-read in full on every reconnect. Toasting from there would put overnight's
   * events on screen each time a control plane restarted, which is how somebody learns to ignore the
   * corner of the page these appear in.
   */
  it('does not toast the durable inbox, only what arrives live', async () => {
    stream.start();
    live.push(': connected\n\n');

    await until(() => stream.events().some((held) => held.id === 'inbox-1'));
    expect(stream.toasts()).toEqual([]);
  });

  /**
   * A host that reboots badly moves a dozen units in one heartbeat. The stack is capped so the
   * incident cannot cover the page somebody is reading during it; nothing is lost, because the inbox
   * is the durable copy and the bell still counts.
   */
  it('caps the stack and keeps the newest', async () => {
    stream.start();
    live.push(': connected\n\n');
    for (const id of ['e-1', 'e-2', 'e-3', 'e-4']) {
      live.push(`data: ${JSON.stringify(event(id))}\n\n`);
    }

    await until(() => stream.toasts().length === 3);
    expect(stream.toasts().map((toast) => toast.id)).toEqual(['e-4', 'e-3', 'e-2']);
  });

  /** The same event from a re-delivering stream is one incident, and must not stack twice. */
  it('does not stack one event twice', async () => {
    stream.start();
    live.push(': connected\n\n');
    live.push(`data: ${JSON.stringify(event('e-1'))}\n\n`);
    await until(() => stream.toasts().length === 1);

    live.push(`data: ${JSON.stringify(event('e-1'))}\n\n`);
    await until(() => stream.events().length > 0);
    expect(stream.toasts().length).toBe(1);
  });

  /** Dismissing one is the only thing a toast can ask of the feed. */
  it('removes a dismissed toast and leaves the feed alone', async () => {
    stream.start();
    live.push(': connected\n\n');
    live.push(`data: ${JSON.stringify(event('e-1'))}\n\n`);
    await until(() => stream.toasts().length === 1);

    stream.dismissToast('e-1');

    expect(stream.toasts()).toEqual([]);
    expect(stream.events().some((held) => held.id === 'e-1')).toBeTrue();
  });

  /**
   * Sign-out drops the toasts with the feed. They are this fleet's incidents drawn over whatever is
   * on screen, and one left up would be in front of whoever signs in next.
   */
  it('clears the toasts when the feed is stopped', async () => {
    stream.start();
    live.push(': connected\n\n');
    live.push(`data: ${JSON.stringify(event('e-1'))}\n\n`);
    await until(() => stream.toasts().length === 1);

    stream.stop();

    expect(stream.toasts()).toEqual([]);
  });
});

describe('mergeEvents', () => {
  /**
   * De-duplication is what makes the stream and a fetch safe to combine, and the events page now
   * needs it for a second pair: a server-filtered inbox and the live stream's matching events. An
   * operator counting incidents must not count one twice because it arrived from both.
   */
  it('merges newest first and counts an event once however many sources carried it', () => {
    const older = { ...event('older'), at: '2026-08-22T11:00:00Z' };
    const newer = { ...event('newer'), at: '2026-08-22T12:00:00Z' };

    const merged = mergeEvents([older, newer], [newer]);

    expect(merged.map((held) => held.id)).toEqual(['newer', 'older']);
  });
});
