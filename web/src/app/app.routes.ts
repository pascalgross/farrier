import { Routes } from '@angular/router';

/**
 * The application's routes.
 *
 * Every page is lazily loaded. The fleet list is the only one most operators open, and making the
 * catalogue and host detail separate chunks keeps the first paint of the page people actually use small.
 */
export const routes: Routes = [
  {
    path: '',
    pathMatch: 'full',
    loadComponent: () => import('./fleet/fleet-list').then((m) => m.FleetList),
    title: 'Fleet — Farrier',
  },
  {
    path: 'hosts/:id',
    loadComponent: () => import('./fleet/host-detail').then((m) => m.HostDetail),
    title: 'Host — Farrier',
  },
  {
    path: 'jobs',
    loadComponent: () => import('./jobs/jobs-list').then((m) => m.JobsList),
    title: 'Jobs — Farrier',
  },
  {
    path: 'catalogue',
    loadComponent: () => import('./catalogue/catalogue').then((m) => m.Catalogue),
    title: 'Operations — Farrier',
  },
  {
    path: 'services',
    loadComponent: () => import('./services/services-page').then((m) => m.ServicesPage),
    title: 'Services — Farrier',
  },
  {
    path: 'events',
    loadComponent: () => import('./events/events-page').then((m) => m.EventsPage),
    title: 'Events — Farrier',
  },
  {
    path: 'alerts',
    loadComponent: () => import('./alerts/alerts-page').then((m) => m.AlertsPage),
    title: 'Alerts — Farrier',
  },
  {
    path: 'templates',
    loadComponent: () => import('./templates/templates-page').then((m) => m.TemplatesPage),
    title: 'Templates — Farrier',
  },
  {
    path: 'fleets',
    loadComponent: () => import('./fleets/fleets-page').then((m) => m.FleetsPage),
    title: 'Fleets — Farrier',
  },
  { path: '**', redirectTo: '' },
];
