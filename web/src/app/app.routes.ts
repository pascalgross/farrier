import { Routes } from '@angular/router';

import { notOperator, notPlatform } from './core/platform-guard';

/**
 * The application's routes.
 *
 * Every page is lazily loaded. The fleet list is the only one most operators open, and making the
 * catalogue and host detail separate chunks keeps the first paint of the page people actually use small.
 *
 * Which credential may reach which route is declared here, with `canMatch`, rather than enforced by the
 * shell. It was a shell effect and that was wrong in a way that looked right: the effect read
 * `Router.url`, a plain property rather than a signal, so it ran when the identity changed and on no
 * later navigation — and the logo in the toolbar links to `/`. See `core/platform-guard.ts`.
 *
 * The guards are a courtesy, not the boundary. The boundary is the control plane, which refuses each
 * credential on the other's routes whatever the browser does; these exist so that an operator meets a
 * page instead of a wall of refusals.
 */
export const routes: Routes = [
  {
    canMatch: [notPlatform],
    path: '',
    pathMatch: 'full',
    loadComponent: () => import('./fleet/fleet-list').then((m) => m.FleetList),
    title: 'Fleet — Farrier',
  },
  {
    canMatch: [notPlatform],
    path: 'hosts/:id',
    loadComponent: () => import('./fleet/host-detail').then((m) => m.HostDetail),
    title: 'Host — Farrier',
  },
  {
    canMatch: [notPlatform],
    path: 'jobs',
    loadComponent: () => import('./jobs/jobs-list').then((m) => m.JobsList),
    title: 'Jobs — Farrier',
  },
  {
    canMatch: [notPlatform],
    path: 'catalogue',
    loadComponent: () => import('./catalogue/catalogue').then((m) => m.Catalogue),
    title: 'Operations — Farrier',
  },
  {
    canMatch: [notPlatform],
    path: 'services',
    loadComponent: () => import('./services/services-page').then((m) => m.ServicesPage),
    title: 'Services — Farrier',
  },
  {
    canMatch: [notPlatform],
    path: 'events',
    loadComponent: () => import('./events/events-page').then((m) => m.EventsPage),
    title: 'Events — Farrier',
  },
  {
    canMatch: [notPlatform],
    path: 'alerts',
    loadComponent: () => import('./alerts/alerts-page').then((m) => m.AlertsPage),
    title: 'Alerts — Farrier',
  },
  {
    canMatch: [notPlatform],
    path: 'templates',
    loadComponent: () => import('./templates/templates-page').then((m) => m.TemplatesPage),
    title: 'Templates — Farrier',
  },
  {
    canMatch: [notOperator],
    path: 'fleets',
    loadComponent: () => import('./fleets/fleets-page').then((m) => m.FleetsPage),
    title: 'Fleets — Farrier',
  },
  {
    // The one route both credentials reach, so it carries no guard: everybody has an account and
    // everybody has a password to change.
    path: 'account',
    loadComponent: () => import('./account/account-page').then((m) => m.AccountPage),
    title: 'Account — Farrier',
  },
  { path: '**', redirectTo: '' },
];
