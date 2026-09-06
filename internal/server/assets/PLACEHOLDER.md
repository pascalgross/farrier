# Embedded web assets

`make web` builds the Angular application and copies its output here, where `embed.FS` picks it up so
that `hostseal-server` is a single binary with the UI inside it. That is the whole deployment: one
binary and PostgreSQL.

This file is committed so the directory always exists — `go:embed` fails to compile against an empty or
absent directory, and a build that breaks when somebody has not run the front-end build first is the
kind of friction that makes a project annoying to contribute to.

When no `index.html` is present here, the server serves a small built-in page explaining how to build
the UI, rather than a 404. Everything under this directory except this file is build output and is
gitignored.
