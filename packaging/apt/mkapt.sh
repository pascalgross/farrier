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
	cd "$OUT_DIR/dists/$SUITE"
	apt-ftparchive \
		-o "APT::FTPArchive::Release::Origin=$ORIGIN" \
		-o "APT::FTPArchive::Release::Label=$ORIGIN" \
		-o "APT::FTPArchive::Release::Suite=$SUITE" \
		-o "APT::FTPArchive::Release::Codename=$SUITE" \
		-o "APT::FTPArchive::Release::Components=$COMPONENT" \
		-o "APT::FTPArchive::Release::Architectures=$ARCHES" \
		-o "APT::FTPArchive::Release::Description=Farrier agent packages for Ubuntu and Debian" \
		release . > Release
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
	sed "s|@@APT_URL@@|$FARRIER_APT_URL|" "$(dirname "$0")/farrier.sources.in" \
		> "$OUT_DIR/farrier.sources"
	echo "mkapt: wrote farrier.sources for $FARRIER_APT_URL"
else
	echo "mkapt: FARRIER_APT_URL unset; farrier.sources not generated" >&2
fi

echo "mkapt: repository built in $OUT_DIR"
find "$OUT_DIR" -type f | sort
