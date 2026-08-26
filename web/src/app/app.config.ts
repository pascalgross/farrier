import { ApplicationConfig, provideBrowserGlobalErrorListeners, provideZonelessChangeDetection } from '@angular/core';
import { provideHttpClient, withFetch } from '@angular/common/http';
import { MAT_FORM_FIELD_DEFAULT_OPTIONS } from '@angular/material/form-field';
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
 *
 * The form-field default is about this application's own house style rather than about taste. Material
 * reserves exactly one line under a field and positions the hint absolutely inside it, which is right
 * for "required" and wrong for the hints written here — every one of them is a sentence explaining what
 * the field is for and why, because that is how the rest of this interface is written. Fixed sizing
 * made each of those sentences overwrite whatever was beneath it. `dynamic` is Material's own answer:
 * the subscript grows with what it holds, and the price is that a field's height changes when an error
 * appears, which is a much smaller problem than a page that reads as broken.
 */
export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideZonelessChangeDetection(),
    provideRouter(routes, withComponentInputBinding()),
    provideHttpClient(withFetch()),
    { provide: MAT_FORM_FIELD_DEFAULT_OPTIONS, useValue: { subscriptSizing: 'dynamic' } },
  ],
};
