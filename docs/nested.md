# Nested ZIP extraction

[Documentation hub](README.md) · [Configuration](configuration.md) · [Recovery](recovery.md)

Use the same ingest pipeline to retain archive samples and add their contents:

```sh
bfsort ingest ./incoming -c ./examples/nested.toml --output ./repository --resume
bfsort stats ./repository
bfsort export ./repository --preset by-format --zip-each-dir --output ./exports --resume
```

The input archive is depth zero and remains a source input. With `max_depth = 2`,
ZIP entries at depths one and two are opened; deeper archives remain stored
samples. Filesystem folder depth does not affect this limit. ZIP-backed DOCX,
XLSX, PPTX, JAR and APK containers can also be expanded. RAR, 7z and other formats
are detected and retained, but their contents are not recursively extracted.

```text
input.zip                       source, depth 0
└── nested.zip                  stored archive, depth 1; opened
    ├── report.pdf              stored child
    └── deeper.zip              stored archive, depth 2; opened
        └── last.zip            stored archive, depth 3; not opened

repository/
├── objects/<prefix>/<sha256>    one object per distinct content hash
├── metadata.sqlite3             original and nested occurrences
├── operations/
│   ├── extraction/*.json        direct-child extraction receipts
│   ├── analysis/*.json          latest outcomes for each analysis root
│   └── trees/*.json             versioned tree identity/completion checkpoints
├── reports/                     run and classification reports
└── views/                       immutable sorted layouts and saved rules
```

Each nested occurrence includes a versioned `nested` object with parent hash,
parent occurrence ID, root source/hash, containing archive depth and entry-index
chain. Direct children of the original input have no parent occurrence because
that outer source is not stored as a sample. Identical bytes are stored once;
different source occurrences retain distinct links. The source SQLite catalog retains these
fields even when a parent archive is outside the selected export group.

## Expand an existing repository

For a standard-mode repository containing ZIP samples:

```sh
bfsort analyze ./malware-2020-repository -c ./examples/nested.toml --dry-run
bfsort analyze ./malware-2020-repository -c ./examples/nested.toml --resume
```

Original downloads are unnecessary. Analysis selects original stored ZIP
occurrences, treating each as a new depth-zero analysis root. It preserves their
historical source fields and adds children linked to their existing occurrence
IDs. Analysis depth is relative to that stored root, not the unavailable original
outer ZIP. Repeated runs reuse extraction receipts and avoid duplicate occurrence
records. Existing sample bytes and original manifest journals remain unchanged.

Dry-run reads metadata and verifies available receipts without decompression or
filesystem changes. It reports candidate occurrences, unique archives, reusable
direct extractions, inaccessible objects and configured limits. Nested work and
expanded sizes cannot be fully predicted without extraction.

## Budgets and failures

`max_total_expanded_bytes` and `max_total_entries` apply separately to each root
tree. Bytes include nested ZIP bytes and all duplicate occurrences. Entries include
directories and rejected names. Reused receipts still charge their complete logical
expansion. Existing per-entry/per-archive limits also apply; the stricter limit wins.
With four active roots and a 20 GiB tree budget, allowances can total 80 GiB. These
are expansion limits, not a cap on total source, repository and export disk usage.

Normal terminal output warns when a tree budget is unlimited. Structured tree
reports include warnings. More depth alone does not bound ZIP bomb expansion.

Outcomes distinguish `completed`, `depth_limit`, `unsupported_format`,
`password_failed`, `invalid_archive`, `resource_limit`, `io_error`, and `cancelled`.
Depth and unsupported-format skips are intentional. Other failures make the run
partial and return a nonzero exit status. Password/malformed archive failures leave
unrelated branches eligible; resource limits, I/O errors and cancellation stop the
affected tree. Successfully recorded samples remain available after failure.

## Resume and saved work

Receipts contain direct-child hashes, entry metadata and logical budget charges,
keyed by archive hash, extractor/detector version and extraction limits. Completed
archives are verified and replayed without decompression. Completed logical usage
is preflighted before any unfinished archive is extracted, including on lowered
budgets. Tree checkpoints reject incompatible depth, extraction-policy and schema
changes; use a fresh destination for those changes. Diagnostic run reports can
still be written on rejection; no new sample occurrences are published. Concurrent roots reuse
compatible extraction results. Incomplete individual archives restart from byte
zero; completed sibling receipts remain reusable. Receipt replay recreates each
parent's distinct child occurrences, rather than copying another parent's IDs.

Objects and receipts are synchronized before completion is published. A crash after
receipt publication but before occurrence publication can replay the receipt. A
partially written manifest line is ignored during recovery. Checksums, versions,
paths, permissions and stored object sizes are validated; standard objects are
hash-verified. Corrupt or missing receipt data fails explicitly. No metadata is
silently repaired or deleted. Lowered tree limits are checked against replayed
logical usage before more extraction; completed work does not reset the budget.

Passwords are never saved in receipts or reports. Correct a protected password
file, then rerun with `--resume`. Successful encrypted extraction can be reused
without retaining a password digest.

Sealed repositories cannot be analyzed or reclassified without explicitly
accessible payloads, and bfsort never changes their security mode automatically.
Sealed ingestion retains a source handle and entry-index locators rather than
one descriptor per pending archive. If an unfinished task needs sealed content,
it re-reads the necessary entries from its accessible original source, without
opening or unlocking stored objects. This additional access cost appears in
`source_replay_bytes` and `source_replay_seconds`; logical tree expansion is charged
once per occurrence, while per-entry streaming limits also apply to access replay.
Choose standard mode before ingestion for efficient further payload processing.

## Update detection without extracting again

```sh
bfsort reclassify ./repository --dry-run
bfsort reclassify ./repository --resume
```

This hash-verifies each unique stored object, detects it once, and updates mismatch
results for all its occurrences. Classification updates commit atomically in SQLite; cancelled work preserves previous committed values. Per-object versioned
checkpoints reuse completed detection. A new view uses saved grouping rules;
repositories created before saved rules were introduced fall back to `by-format`.
Classification and view publication are separate atomic steps: after a crash
between them, rerun reclassification to rebuild the view. Old views and exports
remain snapshots and are not rewritten.

Tree reports include archive reuse/decompression counts, bytes and accumulated
stage durations. Parallel stage totals can overlap and exceed wall time. Hashing occurs inside streaming extraction, so extraction time includes streaming
hash work; `hashing_seconds` and `detection_seconds` expose their measured costs separately. Progress
shows elapsed time and counts. Actual savings depend on the filesystem,
compression and duplicate frequency; use measured results rather than estimates.

Filters also apply to nested ingestion and analysis. Traversal and budget accounting include excluded entries; required archive ancestors are retained as structural SQL records, hidden from ordinary selections. Reclassification accepts the same selectors. Changed nested filter settings require compatible recovery state or a fresh repository.
