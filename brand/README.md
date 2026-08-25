# The mark

A horseshoe, open at the bottom, six nail holes. `farrier-mark.svg` is the master.

It is drawn by [`tools/brandmark`](../tools/brandmark/main.go) rather than by a design tool, because the
same shape has to exist in four files that cannot share one — this master, the copy the Angular
application serves, the copy the documentation site embeds, and a Windows icon for the browser tab — and
four exports from an editor drift apart quietly. Here they are derived from a dozen constants, and
`TestTheCommittedMarkIsWhatThisGeneratorProduces` fails if any of them stops matching.

```bash
make brand      # regenerate every copy after editing the constants
```

Editing one of the generated files by hand is caught by that test rather than by review. Nothing is
generated at build time: the files are committed, so a checkout has the mark without running anything.

| File | Where it shows up |
| --- | --- |
| `brand/farrier-mark.svg` | The master, and the mark at the top of the README |
| `web/public/mark.svg` | The control plane's toolbar — nothing outside `web/public` reaches a browser |
| `tools/docsite/favicon.svg` | The documentation site's tab icon, embedded into the generator |
| `web/public/favicon.ico` | The control plane's tab icon: 16, 32 and 48 pixels |

The three SVGs are the same bytes. They are copies rather than one file because `go:embed` cannot reach
out of its own directory and Angular serves only what is under `web/public`, which is a build system's
limit rather than a decision — and it is the limit the generator and its test exist to make safe.

The one tone is `#b57139`. A favicon is drawn on a tab background the page does not choose, so it has to
hold up on both: this sits between the documentation site's light accent, which vanishes against a dark
tab strip, and its dark one, which washes out against a light one. Every consumer today loads the file
with `<img>`, which gives it no colour to inherit, so the tone is in the file; inlining the path in a
component that should follow the surrounding text is a matter of swapping that one `fill` for
`currentColor` there.

The 16-pixel icon is drawn without the nail holes. At that size a hole is about a pixel across and reads
as dirt on the screen; it is the one place the outputs deliberately differ, and there is a test saying
so, because otherwise it looks like a bug in the hole geometry to whoever finds it next.

## Using it

The mark and the name are **not** covered by the Apache-2.0 licence on the source. What you may and may
not do with them is [`TRADEMARK.md`](../TRADEMARK.md); the short version is that a fork needs its own.
