# bfsort

[Documentation](https://github.com/YounesRabeh/better-file-sorting/blob/main/docs/README.md) · [Commands](https://github.com/YounesRabeh/better-file-sorting/blob/main/docs/commands.md)

Sort local files and ZIP collections with detected-format, original-extension
or mismatch-status presets. Ingest once, retain provenance, then export multiple
independent ZIP collections with portable metadata.

```sh
bfsort ingest ./incoming --extract --security-mode standard -o ./repository --resume
bfsort stats ./repository
bfsort export ./repository --preset by-format --zip-each-dir -o ./exports/by-format --resume
```

`collect` downloads sealed archives; it does not ingest them. Downloads require
explicit authorized access before ingestion. Repository security defaults to
sealed (`0000`); select standard (`0600`) before ingestion to permit exports.
Permissions are not a sandbox. Existing modes never change automatically.

Omitted budgets and deadlines are unlimited. Use an explicitly bounded config
when resource caps are required. Resume verifies completed work; it does not mean
byte-level extraction continuation. Merge and split create independent standard repositories. Metadata is stored in
SQLite. Import occurrences from an existing catalog with `metadata import`.

Linux is the supported runtime platform. See [configuration](https://github.com/YounesRabeh/better-file-sorting/blob/main/docs/configuration.md),
[portable exports](https://github.com/YounesRabeh/better-file-sorting/blob/main/docs/exports.md) and [recovery](https://github.com/YounesRabeh/better-file-sorting/blob/main/docs/recovery.md) for details.
