# Farrier trademark policy

The Farrier **source code** is Apache-2.0 and you may do essentially anything with it.

The Farrier **name and logo** are not covered by that licence. Apache-2.0 §6 says so explicitly:

> This License does not grant permission to use the trade names, trademarks, service marks, or
> product names of the Licensor, except as required for reasonable and customary use in describing
> the origin of the Work […]

This document says what that means in practice, so nobody has to guess.

## Why this file exists at all

Farrier is Apache-2.0 and will stay Apache-2.0 — permanently, because contributions come in under the
DCO and relicensing would need every contributor's agreement. Pegasus Networks has deliberately given
up the ability to take this code proprietary.

The word mark is therefore **the only asset a hosted Farrier business has**. Being straightforward
about that is better than pretending otherwise, and much better than the alternative some projects
reach for, which is keeping a CLA in reserve so the licence can be changed later. We would rather have
a permanent Apache-2.0 licence and a protected name than a revocable licence and a generous one.

Protecting the name also protects you: if anyone can call anything "Farrier", then "we run Farrier"
stops meaning "we run software whose agent has no remote execution channel", and the security claim
this project is built on becomes unverifiable in conversation.

## What you may do without asking

- **Say what you use.** "Runs on Farrier", "compatible with Farrier", "a Terraform provider for
  Farrier", "Farrier monitoring for Nagios". Nominative use — using the name to refer to *our* thing —
  is fine and does not need permission.
- **Fork it.** Fork the repository, keep the name in the repository history, in file headers, in
  import paths, in the `LICENSE` and `NOTICE` files, and in a sentence saying what your fork is
  derived from.
- **Redistribute unmodified builds.** Package our releases for a distribution, mirror the APT
  repository, include the official binaries in an image.
- **Write about it.** Blog posts, talks, books, comparisons, criticism. Especially criticism.
- **Use it commercially.** Run Farrier for your own fleet or for your clients', charge for it, build a
  managed service on it. Apache-2.0 means what it says.

## What needs permission

- **Naming a modified distribution "Farrier".** If you patch the agent, the intent catalogue, or the
  policy enforcement and ship the result, call it something else. "Acme Fleet, based on Farrier" is
  fine and needs no permission. "Farrier" and "Farrier Enterprise" are not.
- **Product names that read as ours.** `farrier-pro`, `Farrier Cloud`, `getfarrier.com`,
  `@farrier/anything`, an APT repository at a domain a user would take for the project's own.
- **Logos and visual identity.** Do not use the Farrier logo for your product, and do not use a
  confusingly similar one.
- **Implying endorsement.** "Official", "certified", "powered by Pegasus Networks", or anything else a
  reasonable reader would take as us vouching for you.

The test is not whether you copied a string; it is whether an ordinary user could end up believing
your software is this project. If they could, ask first.

## The specific case this is really about

Someone will eventually fork Farrier, remove the signature check or add a `shell.exec` intent, and
ship it under a name containing "Farrier". Apache-2.0 lets them do the first two, and this document is
what stops the third.

That matters more here than it would for most projects: the guarantee in
[`docs/SECURITY.md`](docs/SECURITY.md) is a statement about what the software *cannot* do, and a
modified build that quietly can do it, wearing the same name, would make the guarantee worse than
useless.

Please also change the D-Bus names, package name, APT origin (`Farrier`), user account and file paths
in a fork you distribute, so that yours and ours can be installed on the same machine and told apart
in an incident.

## Asking

Open an issue, or write to **trademark@pegasusnetworks.de**. We are not looking for licensing revenue
from the name and we expect to say yes to most reasonable requests; we just want to know.

## Changes

This policy may be updated. It will never be applied retroactively to make previously permitted use
infringing, and any change will be visible in this file's git history.
