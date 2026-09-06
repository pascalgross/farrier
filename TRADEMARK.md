# HostSeal name and logo policy

## Policy issuer

This policy is issued by Pascal Groß.

HostSeal is not currently a registered trademark. This policy describes
the uses of the HostSeal name and logo that Pascal Groß permits. The
policy does not itself create trademark rights. Any enforceable rights
arise from applicable trademark, trade name, title, unfair competition,
and copyright law, as well as from any future trademark registrations.

## What the licence does and does not cover

The HostSeal **source code** is Apache-2.0 and you may do essentially anything with it.

The Apache-2.0 licence does not give you permission to use the HostSeal **name**, or the project's
other identifying signs, as branding or as an indication of origin for your own product. Apache-2.0
§6 says so explicitly:

> This License does not grant permission to use the trade names, trademarks, service marks, or
> product names of the Licensor, except as required for reasonable and customary use in describing
> the origin of the Work […]

The logo file in [`brand/`](brand/hostseal-mark.svg) is part of this repository and is distributed
under the same Apache-2.0 licence as everything else in it; what §6 withholds is the separate
permission to use it as a badge of origin for something that is not this project. Copying the file,
keeping it in a fork, and showing it when you are talking about HostSeal are all covered by the
licence. Putting it on your own product is the case this document is about.

This document says what that means in practice, so nobody has to guess.

## Why this file exists at all

HostSeal is Apache-2.0 and will stay Apache-2.0 — permanently, because contributions come in under the
DCO and relicensing would need every contributor's agreement. Pascal Groß has deliberately given up
the ability to take this code proprietary.

The name is therefore **the only asset a hosted HostSeal business has**. Being straightforward about
that is better than pretending otherwise, and much better than the alternative some projects reach
for, which is keeping a CLA in reserve so the licence can be changed later. We would rather have a
permanent Apache-2.0 licence and a name people can rely on than a revocable licence and a generous
one.

Being careful with the name also helps you: if anyone can call anything "HostSeal", then "we run
HostSeal" stops meaning "we run software whose agent has no remote execution channel", and the
security claim this project is built on becomes unverifiable in conversation.

## What you may do without asking

- **Say what you use.** "Runs on HostSeal", "compatible with HostSeal", "a Terraform provider for
  HostSeal", "HostSeal monitoring for Nagios". Nominative use — using the name to refer to *our* thing —
  is fine and does not need permission.
- **Fork it.** Fork the repository, keep the name in the repository history, in file headers, in
  import paths, in the `LICENSE` and `NOTICE` files, and in a sentence saying what your fork is
  derived from.
- **Redistribute unmodified builds.** Package our releases for a distribution, mirror the APT
  repository, include the official binaries in an image.
- **Write about it.** Blog posts, talks, books, comparisons, criticism. Especially criticism.
- **Use it commercially.** Run HostSeal for your own fleet or for your clients', charge for it, build a
  managed service on it. Apache-2.0 means what it says.

## What needs permission

- **Naming a modified distribution "HostSeal".** If you patch the agent, the intent catalogue, or the
  policy enforcement and ship the result, call it something else. "Acme Fleet, based on HostSeal" is
  fine and needs no permission. "HostSeal" and "HostSeal Enterprise" are not.
- **Product names that read as ours.** `hostseal-pro`, `HostSeal Cloud`, `gethostseal.com`,
  `@hostseal/anything`, an APT repository at a domain a user would take for the project's own.
- **Logos and visual identity.** Do not use the HostSeal logo — the seal in
  [`brand/`](brand/hostseal-mark.svg) — as the mark of your own product, and do not use a confusingly
  similar one.
- **Implying endorsement.** "Official", "certified", "powered by HostSeal", or anything else a
  reasonable reader would take as us vouching for you.

The test is not whether you copied a string; it is whether an ordinary user could end up believing
your software is this project. If they could, ask first.

## The specific case this is really about

Someone will eventually fork HostSeal, remove the signature check or add a `shell.exec` intent, and
ship it under a name containing "HostSeal". Apache-2.0 lets them do the first two. This document does
not by itself make the third unlawful; what it does is state clearly that the third is not a use
Pascal Groß permits, so that nobody can claim it was understood as permitted, and so that it is
plain which rules any legal step would rest on — trademark, trade name, title, unfair competition and
copyright law, together with any registrations that may exist in future.

That matters more here than it would for most projects: the guarantee in
[`docs/SECURITY.md`](docs/SECURITY.md) is a statement about what the software *cannot* do, and a
modified build that quietly can do it, wearing the same name, would make the guarantee worse than
useless.

Please also change the D-Bus names, package name, APT origin (`HostSeal`), user account and file paths
in a fork you distribute, so that yours and ours can be installed on the same machine and told apart
in an incident.

## Asking

Open an issue, or write to **trademark@hostseal.io**. We are not looking for licensing revenue
from the name and we expect to say yes to most reasonable requests; we just want to know.

## Changes

This policy may be updated. It will never be applied retroactively to make previously permitted use
into a use that was not permitted, and any change will be visible in this file's git history.
