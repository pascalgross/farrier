# Farrier web application

The control plane's interface. Angular with Angular Material and Tailwind v4, standalone components,
external `.html` and `.scss` per component, `@if`/`@for` block syntax throughout.

It is built into `internal/server/assets` and embedded with `embed.FS`, so `farrier-server` ships as a
single binary with the interface inside it. That is the whole deployment: one binary and PostgreSQL.

```bash
make web        # build and copy into internal/server/assets
make web-lint   # ESLint, including the doc-comment rule on private members
pnpm start      # dev server on :4200, proxied to a control plane on :8443
```

## What the pages are for

| | |
| --- | --- |
| **Fleet** | Every host and the four things an operator checks first: reachable, security updates outstanding, reboot needed, and whether anything is wrong with the clock or the policy. The last group is the one most dashboards omit, because it only matters once something has already gone wrong |
| **Host** | One host in full. The local policy and the trusted signers get as much space as the inventory, which is unusual and is the point: those two are what bound this control plane, so an operator should be able to see what it could and could not make the host do |
| **Operations** | The complete intent catalogue, including the permanently refused list. Farrier's central claim is about a set being small and closed, and a claim you can check from the running system in one screen is worth much more than the same claim in a README |

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

Phase 0 authenticates operators with a single bearer token, held in `localStorage`. That is a
deliberate trade and it is written down in `src/app/core/token-store.ts`: it is readable by any script
on this origin, which is acceptable only because the control plane serves nothing but its own bundle
from it.

`auth.Provider` on the server is the seam through which OIDC and SAML arrive. Note that operator
authentication is not a boundary the guarantee rests on — a compromised administrator account is
*inside* the threat model in `docs/SECURITY.md` §1 and still cannot run code on an enrolled host.

## Tests

There are none yet. The Angular test harness is scaffolded and works, but component tests would be
testing rendering rather than behaviour at this stage; the behaviour that matters is on the Go side and
is covered there. CI runs the linter and the production build, which catches the failures that actually
happen: a template type error, a missing doc comment, a bundle that has doubled in size.
