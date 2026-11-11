# SQLite repository metadata

Repositories keep payloads as individual SHA-256-addressed files under `objects/`.
The private `metadata.sqlite3` catalog stores occurrences, classifications,
relationships, retained view entries, removals and repository operation history.

## Fresh repositories and import

Schema v3 requires a fresh repository. Re-ingest the original inputs into a
different output directory. Older catalogs are refused, and new detections use
`bfsort-3`.

Each occurrence stores scalar metadata in SQLite columns. Object sizes live in
`objects`, and nested relationships live in `ancestry`. Evidence, alternatives,
and nested entry chains are JSON arrays. Query output still reconstructs the
complete occurrence as JSON.

```sh
bfsort metadata import REPOSITORY SOURCE/metadata.sqlite3
```

`metadata import` opens the source v3 catalog read-only and validates its
records before committing active occurrences, including structural ancestors,
in one destination transaction. Removed source occurrences are excluded. The
destination must already contain the referenced objects with matching sizes and
permissions. Conflicting identities reject the entire import. Use the dataset
commands to copy both occurrences and payloads.

The existing include/exclude extension and format flags, hash, mismatch and size selectors retain their semantics. Selection uses bound SQL parameters. Original filename extensions and detected formats remain independent: an ELF object named `program.pdf` matches extension `pdf` and detected format `elf`.

## Privacy, durability and recovery

The repository and database are private. Metadata remains owner-readable/writable, including catalog journal or sidecar files. Sealed payload permission bits stay unchanged. A metadata query does not authorize opening sealed payload bytes.

Catalog writes enable foreign keys and full synchronization, with rollback journals.
Schema versions are explicit; numeric metadata must fit SQLite signed 64-bit
integers and oversized values are rejected rather than truncated.

Object publication precedes the metadata transaction: an interruption between those steps may leave an unreferenced object, rather than a record pointing at an unpublished object. A successful database commit is authoritative. Existing extraction receipts, export checkpoints and filesystem publication checks continue to govern payload recovery.

Back up or copy the entire repository while its writer is stopped and its repository lock can be acquired. Do not copy only the main SQLite file during a write; a live transaction can involve journal or sidecar state. Preserve the original payload tree, catalog and recovery metadata together. Use supported integrity verification before resuming work on a restored copy.

Preserve damaged repositories and restore them from a consistent backup or a separately validated recovery procedure.

Repository operation records live in the catalog. The `operations/history/`
directory retains lock files for liveness. Collection inventories, download
receipts, reports and recovery checkpoints retain their JSON formats.
