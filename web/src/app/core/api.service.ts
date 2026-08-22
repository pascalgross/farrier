import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

import { CatalogueResponse, FleetResponse, Host } from './api.models';
import { TokenStore } from './token-store';

/**
 * Talks to the Farrier control plane's administrative API.
 *
 * It is the only place in the application that knows a URL or a header. Components take an
 * `Observable` and render it, which means a change to how operators authenticate — a session cookie, an
 * OIDC flow — is one file rather than a search through the components.
 */
@Injectable({ providedIn: 'root' })
export class ApiService {
  /** Angular's HTTP client, injected rather than constructed so tests can supply a fake. */
  private readonly http = inject(HttpClient);

  /** Holds the operator's bearer token. */
  private readonly tokens = inject(TokenStore);

  /**
   * Builds the headers for an authenticated request.
   *
   * The token is read on every call rather than captured once, so that entering a token takes effect
   * immediately instead of on the next reload.
   */
  private headers(): HttpHeaders {
    return new HttpHeaders({ Authorization: `Bearer ${this.tokens.token()}` });
  }

  /** Fetches the fleet. */
  fleet(): Observable<FleetResponse> {
    return this.http.get<FleetResponse>('/api/v1/hosts', { headers: this.headers() });
  }

  /** Fetches one host in full, including its last reported facts, policy and signers. */
  host(id: string): Observable<Host> {
    return this.http.get<Host>(`/api/v1/hosts/${encodeURIComponent(id)}`, {
      headers: this.headers(),
    });
  }

  /**
   * Fetches the complete intent catalogue this control plane knows.
   *
   * The UI shows it in full, including the permanently refused list, because the claim Farrier makes is
   * about that set being small and closed — and a claim an operator can check from the running system
   * in one screen is worth more than the same claim in a README.
   */
  catalogue(): Observable<CatalogueResponse> {
    return this.http.get<CatalogueResponse>('/api/v1/catalogue', { headers: this.headers() });
  }
}
