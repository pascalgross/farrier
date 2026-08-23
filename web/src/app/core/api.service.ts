import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

import {
  CatalogueResponse,
  CreateReadJobRequest,
  FleetResponse,
  Host,
  Job,
  JobsResponse,
} from './api.models';
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

  /** Fetches recent jobs, newest first, optionally narrowed to one host. */
  jobs(hostId?: string): Observable<JobsResponse> {
    const query = hostId ? `?host=${encodeURIComponent(hostId)}` : '';
    return this.http.get<JobsResponse>(`/api/v1/jobs${query}`, { headers: this.headers() });
  }

  /**
   * Fetches every job that is waiting for a second operator.
   *
   * It is a separate request rather than a filter over the list above, and that is the point: the list
   * is bounded, so on a busy fleet a destructive job leaves the newest page within a working day. The
   * second operator the approval model depends on would then have no way to find the one thing they
   * exist to look at.
   */
  jobsAwaitingApproval(): Observable<JobsResponse> {
    return this.http.get<JobsResponse>('/api/v1/jobs?awaiting=true', { headers: this.headers() });
  }

  /**
   * Queues a read-only job.
   *
   * There is deliberately no method here for a destructive one. Such a job carries a signature made
   * offline by a key the control plane does not hold, and a browser is the last place that key should
   * ever be — so the API accepts one and this client cannot produce one, which is the right way round.
   */
  createReadJob(request: CreateReadJobRequest): Observable<Job> {
    return this.http.post<Job>('/api/v1/jobs', request, { headers: this.headers() });
  }

  /**
   * Records this operator's approval of a destructive job.
   *
   * It fails when the operator approving is the one who created the job, which is the point: a
   * destructive job needs a second person. A control plane with one operator account therefore cannot
   * approve one at all, and the message the server returns says so.
   */
  approveJob(id: string): Observable<Job> {
    return this.http.post<Job>(`/api/v1/jobs/${encodeURIComponent(id)}/approve`, null, {
      headers: this.headers(),
    });
  }
}
