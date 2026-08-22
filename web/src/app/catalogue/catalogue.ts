import { Component, computed, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { catchError, of, startWith } from 'rxjs';

import { CatalogueEntry } from '../core/api.models';
import { ApiService } from '../core/api.service';

/**
 * The complete set of operations this control plane can ask a host to perform.
 *
 * This page exists because Farrier's central claim is about a set being small and closed, and a claim an
 * operator can check from the running system in one screen is worth considerably more than the same
 * claim in a README. It shows the permanently refused list alongside the implemented one, for the same
 * reason: what is deliberately absent is as much the product as what is present.
 */
@Component({
  selector: 'farrier-catalogue',
  imports: [
    MatCardModule,
    MatChipsModule,
    MatIconModule,
    MatProgressBarModule,
    MatTableModule,
    MatTooltipModule,
  ],
  templateUrl: './catalogue.html',
  styleUrl: './catalogue.scss',
})
export class Catalogue {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** The columns rendered, in order. */
  protected readonly columns = ['name', 'class', 'authorisation', 'summary'];

  /** The last error message, empty when the catalogue loaded. */
  protected readonly error = signal('');

  /** The catalogue, or null while loading. */
  protected readonly catalogue = toSignal(
    this.api.catalogue().pipe(
      startWith(null),
      catchError(() => {
        this.error.set('The catalogue could not be loaded.');
        return of(null);
      }),
    ),
    { initialValue: null },
  );

  /** Whether the page is still loading. */
  protected readonly loading = computed(() => this.catalogue() === null && !this.error());

  /** Every operation, ordered as the server returned it. */
  protected readonly intents = computed<CatalogueEntry[]>(() => this.catalogue()?.intents ?? []);

  /** The operations this project has permanently refused to implement. */
  protected readonly refused = computed<string[]>(() => this.catalogue()?.refused ?? []);

  /**
   * Describes what authorises an operation, in words rather than as a tier name.
   *
   * "destructive" tells an operator which bucket it is in; "a key this control plane does not hold"
   * tells them what that actually means for them, which is the thing worth knowing.
   */
  protected authorisation(entry: CatalogueEntry): string {
    if (entry.requiresOfflineSignature) {
      return 'a key this control plane does not hold';
    }
    if (entry.class === 'routine') {
      return "the control plane's online key";
    }
    return 'the client certificate alone';
  }
}
