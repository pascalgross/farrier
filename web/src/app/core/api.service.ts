import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

import {
  AlertRuleRequest,
  AlertRulesResponse,
  CatalogueResponse,
  CreateReadJobRequest,
  CreateTemplateRequest,
  EventsResponse,
  FailedServicesResponse,
  FleetResponse,
  Host,
  Job,
  JobsResponse,
  RenderTemplateRequest,
  RenderedTemplate,
  ServiceHistoryResponse,
  StoredTemplateVersion,
  TemplateVersion,
  TemplatesResponse,
  Whoami,
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

  /**
   * Fetches who this credential is and which fleet it acts in.
   *
   * There is no tenant selector to go with it, and that is the design rather than a gap: a credential
   * reaches exactly one fleet, so there is nothing in a request an operator could change to reach
   * another one. This call reports the answer; it does not choose it.
   */
  whoami(): Observable<Whoami> {
    return this.http.get<Whoami>('/api/v1/whoami', { headers: this.headers() });
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
   * Fetches the jobs waiting for a second operator, at the largest bound the control plane accepts.
   *
   * It is a separate request rather than a filter over the list above, and that is the point: the list
   * is bounded, so on a busy fleet a destructive job leaves the newest page within a working day. The
   * second operator the approval model depends on would then have no way to find the one thing they
   * exist to look at.
   *
   * The explicit limit is `store.MaxJobLimit`, asked for rather than defaulted because the default is a
   * fifth of it and the ordering is newest first — so a defaulted request past a hundred waiting jobs
   * would drop the oldest, which for an approval queue are exactly the wrong rows to lose. Callers must
   * still read `truncated`: past five hundred the queue no longer fits any request, and that is a fact
   * the operator has to be shown rather than one this client can absorb.
   */
  jobsAwaitingApproval(): Observable<JobsResponse> {
    return this.http.get<JobsResponse>('/api/v1/jobs?awaiting=true&limit=500', {
      headers: this.headers(),
    });
  }

  /**
   * Queues a job the control plane can authorise by itself.
   *
   * That is a read intent, which needs no signature, or the routine one, which the control plane signs
   * with its own key. There is deliberately no method here for a destructive one: such a job carries a
   * signature made offline by a key the control plane does not hold, and a browser is the last place
   * that key should ever be — so the API accepts one and this client cannot produce one, which is the
   * right way round.
   */
  createReadJob(request: CreateReadJobRequest): Observable<Job> {
    return this.http.post<Job>('/api/v1/jobs', request, { headers: this.headers() });
  }

  /**
   * Records this operator's release of a destructive job.
   *
   * Whether the releaser may be the job's creator depends on the fleet's approval mode, and on the mode
   * as it stood when the job was created rather than now. Under `second_person` this fails for the
   * operator who queued it, and the message the server returns says which setting to change.
   */
  approveJob(id: string): Observable<Job> {
    return this.http.post<Job>(`/api/v1/jobs/${encodeURIComponent(id)}/approve`, null, {
      headers: this.headers(),
    });
  }

  /**
   * Fetches the event inbox, newest first, optionally narrowed to one kind.
   *
   * This is the durable half of the notification design. The live stream tells a tab that happens to
   * be open; this tells the operator asking what they missed overnight, which is the question the
   * whole feature exists for.
   */
  events(kind?: string): Observable<EventsResponse> {
    const query = kind ? `?kind=${encodeURIComponent(kind)}` : '';
    return this.http.get<EventsResponse>(`/api/v1/events${query}`, { headers: this.headers() });
  }

  /** Fetches every host with a failed unit, without opening hosts one at a time. */
  failedServices(): Observable<FailedServicesResponse> {
    return this.http.get<FailedServicesResponse>('/api/v1/services/failed', {
      headers: this.headers(),
    });
  }

  /** Fetches one host's unit-state history, which is what makes "flapping since Tuesday" visible. */
  serviceHistory(hostId: string): Observable<ServiceHistoryResponse> {
    return this.http.get<ServiceHistoryResponse>(
      `/api/v1/hosts/${encodeURIComponent(hostId)}/services/history`,
      { headers: this.headers() },
    );
  }

  /** Fetches this fleet's alerting rules. */
  alertRules(): Observable<AlertRulesResponse> {
    return this.http.get<AlertRulesResponse>('/api/v1/alerts', { headers: this.headers() });
  }

  /** Creates an alerting rule. */
  createAlertRule(request: AlertRuleRequest): Observable<unknown> {
    return this.http.post('/api/v1/alerts', request, { headers: this.headers() });
  }

  /** Changes a rule's threshold, cooldown, recipients or enabled flag. Never its condition. */
  updateAlertRule(id: string, request: AlertRuleRequest): Observable<unknown> {
    return this.http.patch(`/api/v1/alerts/${encodeURIComponent(id)}`, request, {
      headers: this.headers(),
    });
  }

  /** Deletes a rule and the firing state it accumulated. */
  deleteAlertRule(id: string): Observable<unknown> {
    return this.http.delete(`/api/v1/alerts/${encodeURIComponent(id)}`, { headers: this.headers() });
  }

  /** Fetches one summary per provisioning template. */
  templates(): Observable<TemplatesResponse> {
    return this.http.get<TemplatesResponse>('/api/v1/templates', { headers: this.headers() });
  }

  /** Fetches one version of a template in full, defaulting to the latest. */
  template(name: string, version?: number): Observable<TemplateVersion> {
    const query = version ? `?version=${version}` : '';
    return this.http.get<TemplateVersion>(
      `/api/v1/templates/${encodeURIComponent(name)}${query}`,
      { headers: this.headers() },
    );
  }

  /**
   * Stores the next version of a template.
   *
   * There is no update method and no delete, which is the storage model rather than an omission: a
   * host's bootstrap record names a version and must resolve to the bytes that actually ran.
   */
  createTemplate(request: CreateTemplateRequest): Observable<StoredTemplateVersion> {
    return this.http.post<StoredTemplateVersion>('/api/v1/templates', request, {
      headers: this.headers(),
    });
  }

  /**
   * Renders a template to user-data.
   *
   * The response is a credential — it usually carries a freshly minted enrolment token — so it is
   * shown once and nothing stores it, here or on the server. There is deliberately no method that
   * would *deliver* the result to a host: Farrier is not in the delivery path, and a control that
   * implied otherwise would be Tier 3, which is never built.
   */
  renderTemplate(name: string, request: RenderTemplateRequest): Observable<RenderedTemplate> {
    return this.http.post<RenderedTemplate>(
      `/api/v1/templates/${encodeURIComponent(name)}/render`,
      request,
      { headers: this.headers() },
    );
  }
}
