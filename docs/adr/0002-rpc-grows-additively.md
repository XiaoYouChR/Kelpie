# ADR-0002: The protocol grows additively

## Status

Accepted

## Decision

New messages, settings fields, and progress fields are additions to protocol
version 1. The protocol version changes only for a change an older caller
cannot ignore. The Python package checks the Engine Process version during the
handshake and fails the Run with `OUTDATED` when it is too old.

## Context

Released Ghost Downloader builds install the latest Kelpie release. A version
bump would break every older build that installs or updates Kelpie. Kelpie
starts at version 1: Ghost Downloader builds that predate Kelpie install
Python-eD2k and never meet it.

## Consequences

- Older callers keep working against a newer Engine Process: unknown request
  fields default to zero values, and unknown message fields are ignored.
- A newer caller against an older Engine Process is detected by version during
  the handshake, not by waiting for an unknown-message error.
