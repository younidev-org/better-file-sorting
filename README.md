<p align="center">
  <a href="https://github.com/younidev-org/better-file-sorting">
    <img src="assets/better-file-sorting-banner.svg" alt="Better File Sorting — Your files. Your rules." width="100%" />
  </a>
</p>

<div align="center">

  <p>
    <img src="https://img.shields.io/badge/Plagtform-Linux-1793D1?style=for-the-badge&amp;logo=linux&amp;logoColor=white" alt="Supported platform: Linux">
    <a href="https://github.com/younidev-org/better-file-sorting/releases"><img src="https://img.shields.io/badge/Release-View_Releases-2EA44F?style=for-the-badge&amp;logo=github&amp;logoColor=white" alt="View releases"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPL_3.0_or_later-2EA44F?style=for-the-badge" alt="License: GNU GPL v3.0 or later"></a>
    <a href="docs/README.md"><img src="https://img.shields.io/badge/Documentation%20Hub-0969DA?style=for-the-badge&amp;logo=mdbook&amp;logoColor=white" alt="Open the documentation hub"></a>
  </p>

  <p>A command-line tool for sorting files and ZIP collections with configurable policies, deduplication, and optional encrypted ZIP output.</p>

  <p>
    <a href="#features">Features</a> •
    <a href="#showcase">Showcase</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#usage">Usage</a> •
    <a href="#development">Development</a> •
    <a href="#guides">Guides</a>
  </p>
</div>

---

## Features

`bfsort` sorts ordinary files and mixed ZIP collections using detected content,
original extensions or filename/content agreement. It keeps source provenance,
deduplicates repository objects and exports independent portable ZIP collections.
A private SQLite catalog stores metadata and relationships; payloads remain in
the existing SHA-256 object directories.

- Embedded `by-format`, `by-format-or-extension`, `by-extension` and `by-mismatch` presets.
- Precise content detection with explicit unknown/ambiguous results.
- Repository reports without opening sealed payloads.
- Nested ZIP extraction with parent provenance and reusable extraction receipts.
- Existing-repository analysis and resumable reclassification.
- Archive-level ingestion resume and per-ZIP export recovery.
- Metadata queries and filtering, repository verification, diff, merge, split and seeded sampling.
- Operation history/retry, explicit occurrence removal and conservative orphan pruning.
- Readable terminal summaries and clean JSON/CSV output.
- Optional resource budgets and deadlines, protected storage and cancellation.

## Quick start

Download ZIPs from a listing page:

```sh
bfsort collect https://example.org/downloads/ -o ./collection
```

`collect` stores sealed downloads, not an ingested repository. Explicit authorized
access is required before ingestion; bfsort never unlocks files automatically.
For local readable ZIPs, ingest once and create three independent exports:

```sh
bfsort ingest ./incoming --extract --security-mode standard -o ./repository --resume
bfsort stats ./repository
bfsort export ./repository --preset by-format --zip-each-dir -o ./exports/by-format --resume
bfsort export ./repository --preset by-extension --zip-each-dir -o ./exports/by-extension --resume
bfsort export ./repository --preset by-mismatch --zip-each-dir -o ./exports/by-mismatch --resume
```

Omitted application budgets and deadlines are **unlimited**. For explicit caps,
use `-c ./examples/bounded.toml` with ingestion or acquisition. Path, integrity,
permission and technical parser checks remain mandatory. Unlimited operation can
exhaust disk or memory and wait on a stalled server; Ctrl+C remains available.

For nested ZIPs, use [examples/nested.toml](examples/nested.toml). Existing
repositories can be expanded without the original downloads; see the
[nested extraction guide](docs/nested.md).

## Usage

```sh
bfsort ingest ./documents -o ./organized
bfsort ingest ./incoming --extract --dry-run
bfsort ingest ./incoming --extract --zip-each-dir -o ./by-format
bfsort report mismatches ./repository --format csv -o ./mismatches.csv
bfsort reorganize ./repository --preset by-extension
bfsort export ./repository --rules ./examples/rules.example.toml -o ./custom.zip
bfsort config validate -c ./examples/config.example.toml
```

Use `bfsort --help` and `bfsort COMMAND --help` for options. `ingest` is the single
primary ingestion command; the former `organize` alias is removed. `discover`
and `download` provide separate acquisition controls. `reorganize` builds a
repository view; `export` creates independent ZIP outputs. The executable is
lowercase `bfsort`; the Rust library crate is also `bfsort`.

## Showcase

```text
work/
├── collection/                    Original downloaded ZIPs and receipts
├── repository/
│   ├── objects/                   Unique unpacked payloads
│   ├── metadata.sqlite3           Authoritative metadata and relationships
│   ├── views/                     Rule-generated hard links or layout indexes
│   └── operations/                Resume checkpoints
└── exports/
    ├── by-format/                 pdf.zip, pe.zip, elf.zip, ...
    ├── by-extension/              pdf.zip, exe.zip, bin.zip, ...
    └── by-mismatch/               match.zip, mismatch.zip, ambiguous.zip, ...
```

Actual directories depend on selected rules and nonempty categories. Presets
retain every source occurrence; duplicate content can appear multiple times in
exports. Each ZIP includes payloads and a compact JSON export report. Merge, split and reproducible sampling create independent
repositories; see [repository tools](docs/repository-tools.md).
For SQLite catalog layout and imports, see [SQLite metadata](docs/sqlite.md).

## Storage and security

Repositories default to sealed payload permissions (`0000`). Choose `standard`
(`0600`) before ingestion for payload export or analysis. Existing security modes
cannot change automatically. Direct ZIP ingestion uses private temporary standard
storage and leaves source archives untouched; it does not retain a repository or
support resume. Use a persistent repository for recoverable large jobs.

File permissions are not a sandbox. Detection does not execute, render or
unpack hidden payloads; a mismatch is not a malware verdict. Temporary plaintext
can survive forced termination. Export trusts stored identities and does not
rehash source objects. Resume verification does read input bytes and completed
output ZIPs; it skips completed processing, not all I/O.

## Development

Linux is the supported runtime platform. Build with:

```sh
cargo build --release --locked --bin bfsort
target/release/bfsort --version
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
```

Tests use synthetic benign fixtures; HTTP tests start local servers.

## Guides

- [Command reference](docs/commands.md)
- [Configuration and bounded examples](docs/configuration.md)
- [Content detection and mismatch reporting](docs/detection.md)
- [Presets and portable exports](docs/exports.md)
- [Resume and failure recovery](docs/recovery.md)
- [Reliability and validation](docs/validation.md)
