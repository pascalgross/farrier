#!/bin/bash
# Build a signed APT repository as a static file tree, ready to publish to GitHub Pages.
#
# An APT repository is nothing but dists/, pool/, Release and InRelease. GitHub Packages has no APT
# registry, but Pages serves a static tree perfectly well within its limits (roughly 1 GB per file,
# 100 GB of bandwidth a month, public repositories only), and a Farrier agent .deb is a few megabytes.
#
# One suite, "stable", covers every supported release. The agent is a static Go binary with no
# distribution-specific dependencies, so per-codename suites would be five copies of the same file and
# five chances for one of them to go stale.
#
# Usage:
#   FARRIER_APT_URL=https://apt.example.org GPG_KEY_ID=ABCD1234 ./mkapt.sh <deb-dir> <output-dir>
#
# Signing is done with the project GPG key. When GPG_KEY_ID is unset the tree is still built and
# checksummed but left unsigned, which is what CI does to prove the mechanism on every pull request
# without needing the release secret.
set -euo pipefail

DEB_DIR=${1:?usage: mkapt.sh <deb-dir> <output-dir>}
OUT_DIR=${2:?usage: mkapt.sh <deb-dir> <output-dir>}
SUITE=${SUITE:-stable}
COMPONENT=${COMPONENT:-main}
ORIGIN=${ORIGIN:-Farrier}
ARCHES=${ARCHES:-amd64 arm64}

command -v apt-ftparchive >/dev/null 2>&1 || {
	echo "mkapt: apt-ftparchive is required (apt-utils)" >&2
	exit 1
}

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/pool/$COMPONENT/f/farrier-agent"

shopt -s nullglob
debs=("$DEB_DIR"/*.deb)
if [ ${#debs[@]} -eq 0 ]; then
	echo "mkapt: no .deb files in $DEB_DIR" >&2
	exit 1
fi
cp "${debs[@]}" "$OUT_DIR/pool/$COMPONENT/f/farrier-agent/"

for arch in $ARCHES; do
	mkdir -p "$OUT_DIR/dists/$SUITE/$COMPONENT/binary-$arch"
	(
		cd "$OUT_DIR"
		apt-ftparchive --arch "$arch" packages "pool/$COMPONENT" \
			> "dists/$SUITE/$COMPONENT/binary-$arch/Packages"
	)
	gzip -9 -kf "$OUT_DIR/dists/$SUITE/$COMPONENT/binary-$arch/Packages"

	# apt refuses a repository whose Release advertises an architecture with no Packages file, and a
	# Packages file with no Release entry is invisible. Writing both unconditionally, empty if need be,
	# is what keeps a single-architecture build from producing a repository that half works.
	cat > "$OUT_DIR/dists/$SUITE/$COMPONENT/binary-$arch/Release" <<-EOF
		Archive: $SUITE
		Component: $COMPONENT
		Origin: $ORIGIN
		Label: $ORIGIN
		Architecture: $arch
	EOF
done

(
	# Written to a temporary file and moved into place. `apt-ftparchive release . > Release` truncates
	# Release before apt-ftparchive walks the directory, so the file ends up listing itself with the
	# checksum of an empty file — which apt then rejects, at the moment somebody is trying to install.
	cd "$OUT_DIR/dists/$SUITE"
	apt-ftparchive \
		-o "APT::FTPArchive::Release::Origin=$ORIGIN" \
		-o "APT::FTPArchive::Release::Label=$ORIGIN" \
		-o "APT::FTPArchive::Release::Suite=$SUITE" \
		-o "APT::FTPArchive::Release::Codename=$SUITE" \
		-o "APT::FTPArchive::Release::Components=$COMPONENT" \
		-o "APT::FTPArchive::Release::Architectures=$ARCHES" \
		-o "APT::FTPArchive::Release::Description=Farrier agent packages for Ubuntu and Debian" \
		release . > Release.tmp
	mv Release.tmp Release
)

if [ -n "${GPG_KEY_ID:-}" ]; then
	(
		cd "$OUT_DIR/dists/$SUITE"
		gpg --batch --yes --default-key "$GPG_KEY_ID" --clearsign -o InRelease Release
		gpg --batch --yes --default-key "$GPG_KEY_ID" -abs -o Release.gpg Release
	)
	gpg --export "$GPG_KEY_ID" > "$OUT_DIR/farrier-archive-keyring.gpg"
	gpg --export --armor "$GPG_KEY_ID" > "$OUT_DIR/farrier-archive-keyring.asc"
	echo "mkapt: signed with $GPG_KEY_ID"
else
	echo "mkapt: GPG_KEY_ID unset; repository built unsigned (CI mechanism check only)" >&2
fi

if [ -n "${FARRIER_APT_URL:-}" ]; then
	# Anchored to the URIs line. An unanchored substitution also rewrites the placeholder inside the
	# explanatory comment at the top of the template, which then reads as though the decision had been
	# made rather than substituted.
	sed "/^URIs:/ s|@@APT_URL@@|$FARRIER_APT_URL|" "$(dirname "$0")/farrier.sources.in" \
		> "$OUT_DIR/farrier.sources"
	echo "mkapt: wrote farrier.sources for $FARRIER_APT_URL"
else
	echo "mkapt: FARRIER_APT_URL unset; farrier.sources not generated" >&2
fi

# The tree root gets an index.html, because the repository root is a URL like any other: it is printed
# in farrier.sources, in the install instructions and in every release, so sooner or later somebody
# pastes it into a browser. A static host answers that with a 404 — GitHub Pages does not list
# directories — and a 404 at the root of a package repository is indistinguishable from a repository
# that is genuinely broken, which is an expensive thing to have to disprove while a fleet is waiting
# for updates.
#
# The page is self-contained: no stylesheet, no script, no font. This tree is also published as a
# release asset and may be mirrored somewhere that serves nothing else, and a page that renders only
# when the documentation site happens to be beside it would fail in exactly that case.
#
# Written last, so it describes what was built rather than what was intended.
html_escape() {
	# Escapes the four characters that change the meaning of HTML text or of an attribute value. What
	# is interpolated below is a maintainer-set URL and a key fingerprint, neither of which has any
	# business containing one — which is precisely why an unescaped one would go unnoticed until it
	# mattered.
	printf '%s' "${1-}" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

apt_url_html=$(html_escape "${FARRIER_APT_URL:-}")

# What the page may point at is what was actually written, which is not the same on every run: an
# unsigned tree has no InRelease and no keyring, and a tree built without a URL has no farrier.sources.
# A generated page that links to all of them regardless would advertise a repository more complete than
# the one it sits in — the failure this script already refuses to produce for apt, in HTML.
if [ -n "${GPG_KEY_ID:-}" ]; then
	signing_row="<tr><th scope=\"row\">Signing key</th><td><code>$(html_escape "$GPG_KEY_ID")</code></td></tr>"
	signed_items="<li><a href=\"dists/$SUITE/InRelease\">dists/$SUITE/InRelease</a> — the signed index</li>
<li><a href=\"dists/$SUITE/Release.gpg\">dists/$SUITE/Release.gpg</a> — the detached signature</li>
<li><a href=\"farrier-archive-keyring.gpg\">farrier-archive-keyring.gpg</a>
    (<a href=\"farrier-archive-keyring.asc\">armoured</a>) — the archive signing key</li>"
else
	signing_row='<tr><th scope="row">Signing key</th><td>none — this tree was built unsigned</td></tr>'
	signed_items=''
fi

if [ -n "${FARRIER_APT_URL:-}" ]; then
	install_block="<pre><code>curl -fsSL $apt_url_html/farrier-archive-keyring.gpg \\
  | sudo tee /usr/share/keyrings/farrier-archive-keyring.gpg &gt; /dev/null
curl -fsSL $apt_url_html/farrier.sources \\
  | sudo tee /etc/apt/sources.list.d/farrier.sources &gt; /dev/null
sudo apt-get update &amp;&amp; sudo apt-get install farrier-agent</code></pre>"
	sources_item='<li><a href="farrier.sources">farrier.sources</a> — the deb822 source, with
    <code>Signed-By:</code> naming that keyring and nothing wider</li>'
else
	install_block='<p>Built without <code>FARRIER_APT_URL</code>, so this tree carries no
<code>farrier.sources</code> and no instructions naming a host it may not be served from.</p>'
	sources_item=''
fi

package_items=$(
	cd "$OUT_DIR"
	for deb in "pool/$COMPONENT/f/farrier-agent"/*.deb; do
		printf '<li><a href="%s">%s</a></li>\n' "$deb" "${deb##*/}"
	done
)

cat > "$OUT_DIR/index.html" <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Farrier APT repository</title>
<style>
:root { color-scheme: light dark; --bg: #fbfaf8; --ink: #23201c; --soft: #5c554c;
        --rule: #e3ded6; --sunken: #f2efea; --accent: #9a5b2c; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #16150f; --ink: #ece7dd; --soft: #b3aa9c; --rule: #35312a;
          --sunken: #100f0a; --accent: #e0a06a; }
}
body { margin: 0 auto; padding: 2.5rem 1.25rem 4rem; max-width: 46rem; background: var(--bg);
       color: var(--ink); line-height: 1.65;
       font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.05rem; margin: 2.25rem 0 .5rem; }
p.lede { color: var(--soft); margin: 0 0 1.5rem; }
a { color: var(--accent); }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .875rem; }
pre { background: var(--sunken); border: 1px solid var(--rule); border-radius: 6px;
      padding: .875rem 1rem; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: .4rem .75rem .4rem 0; border-bottom: 1px solid var(--rule);
         vertical-align: top; }
th { font-weight: 600; white-space: nowrap; width: 11rem; }
ul { padding-left: 1.2rem; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--rule);
         color: var(--soft); font-size: .875rem; }
</style>
</head>
<body>
<h1>Farrier APT repository</h1>
<p class="lede">This is a Debian package repository, not a page to read. Point
<code>apt</code> at it rather than a browser.</p>

<h2>Installing the agent</h2>
$install_block
<p>The agent installs with no keys in <code>/etc/farrier/trusted-signers</code> and a policy that
permits security updates and nothing else.</p>

<h2>What this repository is</h2>
<table>
<tr><th scope="row">Suite</th><td><code>$SUITE</code></td></tr>
<tr><th scope="row">Component</th><td><code>$COMPONENT</code></td></tr>
<tr><th scope="row">Architectures</th><td><code>$ARCHES</code></td></tr>
$signing_row
</table>
<p>One suite covers every supported release: the agent is a static Go binary with no
distribution-specific dependencies, so per-codename suites would be copies of the same file and as
many chances for one of them to go stale.</p>

<h2>Files</h2>
<ul>
$signed_items
<li><a href="dists/$SUITE/Release">dists/$SUITE/Release</a> — the index itself</li>
$sources_item
</ul>

<h2>Packages</h2>
<ul>
$package_items
</ul>

<footer>
Built by <a href="https://github.com/pascalgross/farrier">Farrier</a>. Fleet management for Ubuntu and
Debian servers, without a remote shell.
</footer>
</body>
</html>
HTML

echo "mkapt: repository built in $OUT_DIR"
find "$OUT_DIR" -type f | sort
