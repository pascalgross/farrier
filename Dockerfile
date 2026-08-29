# syntax=docker/dockerfile:1

# The control plane as a container image.
#
# Only farrier-server is in here, and that is a security decision rather than a size one. `farrier` —
# the command that signs a destructive job — links the signing backends, and a signing key that the
# control plane's own host can reach is a key the control plane holds, whatever the console says about
# custody. Signing happens on somebody's laptop or against their token; see docs/SECURITY.md §1 and §9.
#
# The agent is not here either, and never will be: it manages a host, and a host it managed from inside
# a container on the control plane would be the control plane.

# The web application first, so that a change to Go source does not rebuild node_modules and a change to
# the front end does not rebuild the world. It is copied into internal/server/assets in the next stage,
# which is the directory embed.FS reads — the same arrangement `make web` produces locally.
FROM node:22-alpine AS web
WORKDIR /src/web
# pnpm 10, the major CI uses, from npm rather than through corepack: there is no packageManager field in
# web/package.json for corepack to read, so it would need the version spelled out here anyway. What
# makes the result reproducible is --frozen-lockfile below, not this line; pin an exact pnpm version
# here if you need two builds of the same commit to be byte-identical.
RUN npm install --global pnpm@10
# The lockfile and manifest alone, so the dependency layer is cached against every change to the
# application source.
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm run build

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Over the top of the placeholder the repository commits so that go:embed has a directory to read.
COPY --from=web /src/web/dist/ internal/server/assets/

# Stamped rather than compiled in from a constant, so that an image built from a tag and one built from
# a branch are distinguishable in a heartbeat. `make image` passes both.
ARG VERSION=0.0.0-docker
ARG COMMIT=unknown

# CGO_ENABLED=0 for the same reason the released binary is built that way: a static binary needs no
# runtime libraries in the final image, so there is nothing in it to keep patched but the binary itself.
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X github.com/pascalgross/farrier/internal/buildinfo.Version=${VERSION} \
        -X github.com/pascalgross/farrier/internal/buildinfo.Commit=${COMMIT}" \
      -o /out/farrier-server ./cmd/farrier-server

FROM alpine:3.22

# ca-certificates for the two things the control plane calls out to — a webhook endpoint and an SMTP
# relay — neither of which can be verified without root certificates. curl is the healthcheck below,
# and is worth its couple of megabytes for the ordinary case where somebody has to get inside a running
# container and find out what the server answers.
RUN apk add --no-cache ca-certificates curl tzdata

# A fixed uid, not just a name. The CA directory is a volume, and a volume's ownership survives the
# image that created it: a uid that moved between releases would leave a running installation unable to
# read its own certificate authority.
RUN addgroup -g 65532 -S farrier \
 && adduser -u 65532 -S -G farrier -H -s /sbin/nologin farrier \
 && mkdir -p /var/lib/farrier-server \
 && chown farrier:farrier /var/lib/farrier-server

COPY --from=build /out/farrier-server /usr/bin/farrier-server
# --chmod rather than relying on the mode in the build context: a checkout on a filesystem that does not
# carry the executable bit would otherwise produce an image whose entry point cannot be run, and the
# error for that names the shell rather than the file.
COPY --chmod=0755 deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Re-declared: an ARG is scoped to the stage that declares it, so without this line the label below
# would read the empty string and the image would claim no version at all.
ARG VERSION=0.0.0-docker

# What a registry shows about this image, and what a vulnerability scanner reports it as. The source
# link is the one that matters: the guarantee this project makes is checkable only against source, so an
# image that did not say where it came from would be asking to be taken on trust.
LABEL org.opencontainers.image.title="farrier-server" \
      org.opencontainers.image.description="Farrier control plane: fleet management with no remote execution channel" \
      org.opencontainers.image.source="https://github.com/pascalgross/farrier" \
      org.opencontainers.image.documentation="https://github.com/pascalgross/farrier/blob/main/deploy/README.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Pascal Groß, trading as Pegasus Networks" \
      org.opencontainers.image.version="${VERSION}"

# Declared so that a `docker run` without a volume still keeps the CA, the online signing key and the
# template sealing key out of the container's writable layer. Losing any of them is not recoverable:
# every enrolled agent verifies this control plane against that CA, and every stored template is
# encrypted to that key. deploy/compose.yaml names a volume for it explicitly.
VOLUME /var/lib/farrier-server

USER farrier
EXPOSE 8443

# --insecure is correct here and nowhere else. The certificate this reaches is the one the server
# presents on its own loopback, which on a default installation is issued by Farrier's own CA and is not
# in this image's trust store; the check is asking whether the process is up and can reach its database,
# which is exactly what /healthz answers. Nothing about the agent protocol's own verification is
# affected: an agent verifies against the CA bundle it was handed at enrolment.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS --insecure https://127.0.0.1:8443/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve"]
