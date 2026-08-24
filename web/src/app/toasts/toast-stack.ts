import { Component, inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { RouterLink } from '@angular/router';

import { EventStream } from '../core/event-stream';
import { FleetEvent } from '../core/api.models';
import { describeKind } from '../core/event-kinds';
import { toneClass } from '../core/tone';

/**
 * The in-app notification: what the live stream just delivered, in the corner of whatever page the
 * operator is on.
 *
 * It exists because the persona issue #4 is about — somebody with the dashboard open in a tab — was
 * the one the shipped feature reached least. The inbox answers "what did I miss overnight" and the
 * bell counts, but a badge that increments in silence is not a notification; the operator has to
 * already be looking at the corner it lives in. This is the half that arrives without being looked
 * for.
 *
 * **Nothing here is actionable, and that is a constraint rather than a stage of development.** A
 * toast carries a summary and at most one link, which navigates to a host page or to the inbox.
 * There is no approve button and no retry button, because anything that changes state goes through
 * the admin API with its normal authentication — and a destructive job still needs an offline
 * signature this control plane cannot produce and a second person to release it. The only control on
 * a toast is the one that removes the toast. `toast-stack.spec.ts` pins that: it walks everything
 * interactive the component renders and fails on anything that is not the dismiss button or a link
 * to a page.
 *
 * It lives in the shell rather than on a page because the shell is the only component that is always
 * mounted, which is the same reason the bell is there. A toast that only appeared on the events page
 * would be a toast for the operator who least needs one.
 */
@Component({
  selector: 'farrier-toast-stack',
  imports: [MatButtonModule, MatIconModule, RouterLink],
  templateUrl: './toast-stack.html',
  styleUrl: './toast-stack.scss',
})
export class ToastStack {
  /** The live feed, which is where a toast comes from and the only thing this component talks to. */
  private readonly stream = inject(EventStream);

  /** The events on screen, newest first, capped and expired by the feed rather than by this page. */
  protected readonly toasts = this.stream.toasts;

  /** The label for an event's kind, from the one table the whole application renders kinds with. */
  protected label(event: FleetEvent): string {
    return describeKind(event.kind).label;
  }

  /** The icon for an event's kind. */
  protected icon(event: FleetEvent): string {
    return describeKind(event.kind).icon;
  }

  /** The colour class for an event's kind. */
  protected tone(event: FleetEvent): string {
    return toneClass(describeKind(event.kind).tone);
  }

  /**
   * Takes one toast off the stack.
   *
   * Also called when the operator follows a toast's link: they have gone where it pointed, so the
   * notification has done its whole job and leaving it up would cover the page it sent them to.
   */
  protected dismiss(id: string): void {
    this.stream.dismissToast(id);
  }
}
