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
    path: 'catalogue',
    loadComponent: () => import('./catalogue/catalogue').then((m) => m.Catalogue),
    title: 'Operations — Farrier',
  },
  { path: '**', redirectTo: '' },
];
