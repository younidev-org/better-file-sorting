# Presets and portable exports

[Documentation hub](README.md) · [Commands](commands.md) · [Recovery](recovery.md)

Ingest a mixed collection once, then export independent views without reopening
original archives or repeating classification:

```sh
bfsort ingest ./incoming --extract --security-mode standard -o ./repository --resume
bfsort export ./repository --preset by-format --zip-each-dir -o ./exports/by-format --resume
bfsort export ./repository --preset by-extension --zip-each-dir -o ./exports/by-extension --resume
bfsort export ./repository --preset by-mismatch --zip-each-dir -o ./exports/by-mismatch --resume
```

Each output is independent. Source objects, original inputs and existing view
pointers remain unchanged. Parent output directories are created privately when
needed. A sealed repository supports export preview, not payload export.

## Choose a preset

| Preset | Groups by | Example output ZIPs |
| --- | --- | --- |
| `by-format` (default) | Saved MIME type with optional short aliases | `pdf.zip`, `mime/image/svg+xml.zip`, `undetected.zip` |
| `by-extension` | Original final filename extension, case-insensitively | `pdf.zip`, `exe.zip`, `bin.zip` |
| `by-mismatch` | Saved extension/content agreement status | `match.zip`, `mismatch.zip`, `ambiguous.zip` |

Only nonempty groups produce ZIPs. Missing extensions use the sanitized `_` group.
By-extension grouping does not establish actual content: PE files named `.pdf`
remain in `pdf.zip`. By-format puts recognizable PE executables in `pe.zip`,
regardless of their original names. A mismatch is not a malware verdict.

Presets retain all source occurrences consistently, including repeated hashes.
If a hash appears more than once in a group, filenames receive deterministic
occurrence suffixes; the exported ZIP can therefore contain repeated content.
Use custom `--rules` when you want `first_only` or another duplicate policy.
Do not combine `--rules` and `--preset`.

## Automatic grouping with optional explicit rules

`by-format` uses a short alias such as `pdf` when available. A MIME type without
an alias gets its own path, for example `mime/image/svg+xml/`. With
`--zip-each-dir`, BFSORT writes a ZIP for each complete format group, such as
`mime/image/svg+xml.zip`. Generic MIME results go to `undetected/`.
Choose `by-extension` to group by the final suffix of the original filename.

Use the directory-only `{format_group}` template in custom rules that also
override selected groups. See
[rules.automatic.example.toml](../examples/rules.automatic.example.toml).

## Payload names

`--naming sample` is the default and keeps the rule-planned sample names. Repository
views retain their existing naming policy regardless of export naming.
`--naming original` uses each stored original stem and extension; extensions are
normalized to lowercase. Missing original extensions fall back to `.sample`.
`--naming detected` uses the original stem with the saved detected format's canonical
extension. Both options sanitize names and resolve collisions deterministically.
They can produce executable or script suffixes when explicitly selected.

```sh
bfsort export ./repository --naming original -o ./original-names.zip
bfsort export ./repository --naming detected -o ./detected-names.zip
```

Detected extension mappings differ from format identifiers for PE (`exe`),
JavaScript (`js`), PowerShell (`ps1`), Python (`py`), shell (`sh`), batch (`bat`),
text (`txt`), gzip (`gz`), bzip2 (`bz2`), JPEG (`jpg`), TIFF (`tif`), Java class
(`class`) and Zstandard (`zst`). Other known formats use their identifier as the
extension, including `elf`, `macho`, `cfb`, and `7z`. Unknown, ambiguous and
unevaluated detections use `.sample`; there is no filename-extension fallback
under detected naming.

## ZIP structure

Export writes one ZIP for the full selection by default. A directory destination
contains `archive.zip` and a collection-wide `export.sqlite3`. With
`--zip-each-dir`, that directory contains the grouped ZIPs and the same
collection-wide database. Each ZIP also has an index for its own contents.

```text
exports/
├── export.sqlite3
└── archive.zip
    ├── pdf/
    │   └── <sha256>.sample
    ├── export.json
    └── export.sqlite3
```

An explicit `-o ./files.zip` writes `files.zip` and `files.sqlite3` beside it.

`export.json` is a compact report declaring `kind = "bfsort-export"`,
`schema_version = 3`, and tool version. It reports payload and occurrence counts,
unique object counts, logical/payload byte totals, and SHA-256 fingerprints of the
planned layout and effective selected metadata. It also records the index SHA-256.
Each index contains one row per exported payload, with its path inside the ZIP,
original entry name, SHA-256, size, detected format, family, MIME type, and
mismatch status. The detected format displays the short alias or the MIME type,
with `undetected` for generic results. The collection index uses `archive_path` to name the ZIP
relative to the index, including any subdirectories. Inside a ZIP the column
is empty because every row belongs to that archive.

ZIP encryption covers the two metadata entries inside each ZIP. The
collection-wide index is an owner-only plaintext file and lists the metadata
for password-protected ZIPs as well. Passwords and keys are never included.

To browse the collection with the SQLite CLI:

```sh
sqlite3 -readonly ./exports/export.sqlite3 \
  'SELECT archive_path, path, detected_format FROM entries ORDER BY archive_path, path LIMIT 20;'
```

Normal export trusts repository content identities; it does not rehash source
objects or perform an integrity audit. Resumable export hashes completed ZIPs to
detect changes. Recovery after publication without a saved receipt checks the
report fingerprints, the SQLite index, and every planned payload path, size and hash.
Resume rebuilds a missing collection index after verifying the ZIPs and refuses
to overwrite a modified index. Use a fresh destination for older exports.
See [recovery](recovery.md).

## Storage requirements

An extracted repository retains unique object content. Hard-link views do not
add another payload copy. Each exported collection is an additional compressed
copy. Peak storage includes staging/output ZIPs as well as source archives and
repository objects. Compression ratios are data-dependent.

Nested provenance remains in the source repository catalog. ZIP exports are
payload collections with a browsing index and a compact report.

## Compression cost

`--compression-level 0` stores entries without compression; `1` selects fast Deflate, and `9` favors size. Omit it to retain the library default. Ingest ZIP output and repository export accept the same option. Runtime TOML uses `compression_level = 1`. Resume fingerprints include the compression setting; use the same setting on retries. Changing it requires a fresh output/checkpoint.

```sh
bfsort export ./repository --include-format pdf --naming detected --compression-level 0 -o ./pdfs.zip
```

Stored ZIPs can be larger, but avoid recompressing already-compressed content. Neither mode changes payload bytes or integrity requirements.
