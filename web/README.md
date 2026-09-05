# HostSeal web application

The control plane's interface. Angular with Angular Material and Tailwind v4, standalone components,
external `.html` and `.scss` per component, `@if`/`@for` block syntax throughout.

It is built into `internal/server/assets` and embedded with `embed.FS`, so `hostseal-server` ships as a
single binary with the interface inside it. That is the whole deployment: one binary and PostgreSQL.

```bash
make web        # build and copy into internal/server/assets
make web-lint   # ESLint, including the doc-comment rule on private members
pnpm exec ng test --watch=false
pnpm start      # dev server on :4200
```

`pnpm start` serves the application alone; point it at a control plane with `proxy.conf.json` if you
want the API alongside it. Most work on this application is faster against `hostseal-server serve`
directly, which embeds the built bundle and needs no proxy at all.

## What the pages are for

| | |
| --- | --- |
| **Fleet** | Every host and the four things an operator checks first: reachable, security updates outstanding, reboot needed, and whether anything is wrong with the clock or the policy. The last group is the one most dashboards omit, because it only matters once something has already gone wrong |
| **Host** | One host in full. The local policy and the trusted signers get as much space as the inventory, which is unusual and is the point: those two are what bound this control plane, so an operator should be able to see what it could and could not make the host do |
| **Operations** | The complete intent catalogue, including the permanently refused list. HostSeal's central claim is about a set being small and closed, and a claim you can check from the running system in one screen is worth much more than the same claim in a README |

## Conventions

- **A doc comment on every declaration, including private class members.** ESLint's
  `jsdoc/require-jsdoc` runs with `publicOnly` disabled, matching what `tools/doccheck` enforces on the
  Go side. A private field holding an injected service is exactly the kind of declaration whose reason
  for existing is invisible from its signature. Whether the comment explains *why* is left to review;
  `CONTRIBUTING.md` says so rather than pretending a linter covers it.
- **Nothing is inferred that the agent did not report.** A cell that guessed would eventually guess
  wrong about the host somebody was looking at during an incident. "Not reported yet" is shown rather
  than a blank, because a blank reads as "nothing to say" and this means "the host has not told us".
- **The palette is defined once**, in `src/tailwind.css`. A colour that means "offline" means that
  everywhere; a dashboard whose colours drift is one people stop reading.
- **Tailwind lives in a plain `.css` file** rather than in `styles.scss`, because Sass deprecated
  `@import` and Tailwind v4's directive is not something `@use` can express.

## Authentication

The control plane authenticates operators with a single bearer token, held in `localStorage`. That is a
deliberate trade and it is written down in `src/app/core/token-store.ts`: it is readable by any script
on this origin, which is acceptable only because the control plane serves nothing but its own bundle
from it.

`auth.Provider` on the server is the seam through which OIDC and SAML arrive. Note that operator
authentication is not a boundary the guarantee rests on — a compromised administrator account is
*inside* the threat model in `docs/SECURITY.md` §1 and still cannot run code on an enrolled host.

## Tests

`src/app/core/format.spec.ts` covers the formatters, which is where the one genuine defect in this
application lived: `formatOffset` rendered a positive clock offset as "behind" when the agent reports
local-minus-server, so a host running ahead was described as running behind. The page rendered, the
number was right, and only the word was wrong — which is exactly the kind of thing a spec catches and a
review does not.

Component specs exist only where the thing worth pinning lives in a template rather than behind it,
which is a narrow set and deliberately stays narrow. Two qualify today. `services-page.spec.ts` pins
what each number in the header counts: the list holds hosts that are failing, hosts whose unit list was
truncated and hosts nothing is known about, and reading its length as the failing count made one
failure on a fleet of three hundred read as trouble on six machines. `toast-stack.spec.ts` pins that a
notification is never actionable — it walks every interactive element the toast renders and fails on
anything that is not the dismissal or a link to a page, because the failure it guards against is
somebody adding a control, not somebody changing one.

Everything else the specs cover is a pure function: the formatters, the unit-condition table in
`core/unit-state.ts`, and the event merge. CI runs the specs, the linter and the production build,
which between them catch the failures that actually happen: a template type error, an input that is
never bound, a missing doc comment, a bundle that has doubled in size.
