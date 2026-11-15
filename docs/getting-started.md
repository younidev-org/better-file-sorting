# Getting started

[Documentation](README.md) · [Command reference](commands.md) · [Configuration](configuration.md)

Use a Linux binary from [GitHub Releases](https://github.com/younidev-org/better-file-sorting/releases) or [build from source](development.md#build). Run `bfsort --help` to list commands.

## Extract or organize local inputs

Extract one readable ZIP into a fresh directory without creating a catalog:

```sh
bfsort ingest --unzip-only ./archive.zip --security-mode standard -o ./extracted
```

Pass `--extract` to classify ZIP members and store them in a repository. For ordinary files, run `bfsort ingest ./documents -o ./organized`.

```sh
bfsort ingest ./incoming --extract --security-mode standard --resume -o ./repository
bfsort stats ./repository
bfsort export ./repository --preset by-format --zip-each-dir -o ./exports
```

Choose `--security-mode standard` for readable owner-only payloads (`0600`) and later exports. Repositories otherwise default to sealed payloads (`0000`). Set the mode when creating the repository. For nested archives, see [Nested extraction](nested.md).

## Collect ZIPs from the web

```sh
bfsort collect https://example.org/downloads/ -o ./collection
```

Downloads start sealed. Explicitly grant access to the archives you are authorized to ingest, then use receipt-driven ingestion from the project directory:

```sh
bfsort ingest --extract --security-mode standard --resume -o ./repository
```

Use [the collection example](../examples/collection.example.toml) to configure another staging location. Omitted application limits and deadlines are unlimited. Use [the bounded example](../examples/bounded.toml) to configure caps.

## Find the output

```text
work/
├── collection/             Original downloads and receipts
├── repository/
│   ├── metadata.sqlite3    Occurrences, classifications, and references
│   ├── objects/            Unique payloads stored by SHA-256
│   ├── views/              Organized repository layouts
│   └── operations/         Recovery state
└── exports/                Standalone ZIPs with compact export reports
```

For an older catalog, re-ingest the original inputs into a fresh directory. See [SQLite metadata](sqlite.md) and [Recovery](recovery.md).
