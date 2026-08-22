import { ApplicationConfig, provideBrowserGlobalErrorListeners, provideZonelessChangeDetection } from '@angular/core';
import { provideHttpClient, withFetch } from '@angular/common/http';
import { provideRouter, withComponentInputBinding } from '@angular/router';

import { routes } from './app.routes';

/**
 * The application's providers.
 *
 * `withFetch` is passed deliberately: the control plane's administrative API is plain JSON over HTTPS
 * and the fetch backend is what the browser is optimised for. Zoneless change detection is used because
 * every piece of state in this application is a signal, so there is nothing for zone.js to patch and no
 * reason to pay for it.
 *
 * `withComponentInputBinding` is required, not optional: `HostDetail` takes the `:id` route parameter
 * as `input.required<string>()`, and without this the input is never set and the host page throws on
 * every load. It fails at run time rather than at build time, which is why it is worth a sentence here.
 */
export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideZonelessChangeDetection(),
    provideRouter(routes, withComponentInputBinding()),
    provideHttpClient(withFetch()),
  ],
};
