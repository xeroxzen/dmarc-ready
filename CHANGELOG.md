# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Sender classes, verdicts and JSON field names are part of the public interface: renaming or removing one is a breaking change.

## [0.1.0] - 2026-11-06

### Added

- Reads DMARC aggregate reports as `.xml`, `.xml.gz` or `.zip`, including the `dmarc-2.0` namespace.
- Classifies each sending IP as `aligned`, `partly-aligned`, `unaligned` or `unauthenticated`.
- Verdicts: `ready`, `not-ready`, `insufficient-data`.
- CLI with text and JSON output, optional reverse-DNS names, and meaningful exit codes.
- Hardened parsing: defusedxml with DTDs forbidden, and caps on file size, decompressed size, zip members and records.

[0.1.0]: https://github.com/xeroxzen/dmarc-ready/releases/tag/v0.1.0
