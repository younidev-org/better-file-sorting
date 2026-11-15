<p align="center">
  <a href="https://github.com/younidev-org/better-file-sorting">
    <img src="assets/better-file-sorting-banner.svg" alt="Better File Sorting — Your files. Your rules." width="100%" />
  </a>
</p>

<div align="center">

  <p>
    <img src="https://img.shields.io/badge/Platform-Linux-1793D1?style=for-the-badge&amp;logo=linux&amp;logoColor=white" alt="Supported platform: Linux">
    <a href="https://github.com/younidev-org/better-file-sorting/releases"><img src="https://img.shields.io/badge/Release-View_Releases-2EA44F?style=for-the-badge&amp;logo=github&amp;logoColor=white" alt="View releases"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPL_3.0_or_later-2EA44F?style=for-the-badge" alt="License: GNU GPL v3.0 or later"></a>
    <a href="docs/README.md"><img src="https://img.shields.io/badge/Documentation%20Hub-0969DA?style=for-the-badge&amp;logo=mdbook&amp;logoColor=white" alt="Open the documentation hub"></a>
  </p>

  <p>A command-line tool for sorting files and ZIP collections with configurable policies, deduplication, and optional encrypted ZIP output.</p>

  <p>
    <a href="#quick-start">Quick Start</a> •
    <a href="docs/README.md">Documentation</a> •
    <a href="docs/development.md">Development</a>
  </p>
</div>

---

## Quick start

Download a Linux binary from [GitHub Releases](https://github.com/younidev-org/better-file-sorting/releases) or [build from source](docs/development.md#build).

Sort a directory of readable ZIPs and export one ZIP per detected format:

```sh
bfsort ingest ./incoming --extract --security-mode standard --resume -o ./repository
bfsort stats ./repository
bfsort export ./repository --preset by-format --zip-each-dir -o ./exports
```

For plain extraction, use `bfsort ingest --unzip-only ./archive.zip --security-mode standard -o ./extracted`.

## Documentation

| Start here | What you’ll find |
| --- | --- |
| [Getting started](docs/getting-started.md) | Local files, web collections, and repository layout |
| [Command reference](docs/commands.md) | Command examples, flags, and output controls |
| [Configuration](docs/configuration.md) | TOML settings, sorting rules, and resource limits |
| [Repository and recovery](docs/README.md#manage-a-repository) | Queries, verification, cleanup, and resume |
| [All guides](docs/README.md) | Detection, nested ZIPs, exports, and datasets |
