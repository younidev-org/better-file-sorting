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
| `by-format` (default) | Saved content detection | `pdf.zip`, `pe.zip`, `elf.zip`, `unknown.zip` |
| `by-format-or-extension` | Medium/high-confidence detected content, otherwise original extension | `detected/pdf.zip`, `undetected/extension-foo.zip`, `undetected/no-extension.zip`, `ambiguous.zip` |
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

```sh
bfsort export ./repository --preset by-format-or-extension --zip-each-dir -o ./exports/automatic --resume
```

No format/extension list is required. Medium/high-confidence identified formats
use `detected/<format>/`. Unknown, unevaluated and low-confidence content uses
`undetected/extension-<extension>/`, or `undetected/no-extension/` when no usable
extension exists. Conflicting detection uses `ambiguous/`. For example, generic
printable text has low confidence and falls back to its filename extension.
Fallback names are lowercase and sanitized; they do not establish content format.
Every occurrence is retained, including duplicate hashes. Only nonempty groups
produce ZIPs. New detector identifiers and arbitrary extensions become groups
automatically. The existing `by-format` default remains available unchanged.

With this grouping, `--zip-each-dir` creates a ZIP for each complete destination
directory (`detected/pdf.zip`, rather than a combined `detected.zip`). Custom rules
using `{format_or_extension}` get the same behavior, including their explicit
override groups. Other rules/presets keep their top-level ZIP grouping.
Explicit `--zip-dir` selections still include the selected directory's descendants.

For automatic fallback **and** explicit selections in one run, use
[rules.automatic.example.toml](../examples/rules.automatic.example.toml):

```toml
[organization]
duplicates = "all"
default_directory = "{format_or_extension}"

[[rules]]
name = "selected-pdfs"
[rules.match]
detected_format = "pdf"
[rules.output]
directory = "selected-pdfs"
filename = "{sha256}.sample"
```

Run with `--rules examples/rules.automatic.example.toml` instead of `--preset`.
The first matching rule controls its output; everything else gets the automatic
fallback. `{format_or_extension}` is a directory-only placeholder. Detection,
confidence and original extension remain separately recorded in the repository catalog.

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

```text
pdf.zip
├── pdf/
│   ├── <sha256>.sample
│   └── <sha256>-<occurrence-id>.sample
└── export.json
```

`export.json` is a compact report declaring `kind = "bfsort-export"`,
`schema_version = 2`, and tool version. It reports payload and occurrence counts,
unique object counts, logical/payload byte totals, and SHA-256 fingerprints of the
planned layout and effective selected metadata. It does not export individual
occurrence records, provenance paths, `layout.jsonl`, or `manifest.jsonl`.
Passwords and encryption keys are never included. With output encryption, the
report is encrypted with the payload entries.

Normal export trusts repository content identities; it does not rehash source
objects or perform an integrity audit. Resumable export hashes completed ZIPs to
detect changes. Recovery after publication without a saved receipt checks the
report fingerprints and every planned payload path, size and hash. Resume
requires the compact export report. Use a fresh destination to recreate an
export with obsolete indexes. See [recovery](recovery.md).

## Storage requirements

An extracted repository retains unique object content. Hard-link views do not
add another payload copy. Each exported collection is an additional compressed
copy. Peak storage includes staging/output ZIPs as well as source archives and
repository objects. Compression ratios are data-dependent.

Nested provenance remains in the source repository catalog. ZIP exports are
payload collections with a compact report, not independent repositories.

## Compression cost

`--compression-level 0` stores entries without compression; `1` selects fast Deflate, and `9` favors size. Omit it to retain the library default. Ingest ZIP output and repository export accept the same option. Runtime TOML uses `compression_level = 1`. Resume fingerprints include the compression setting; use the same setting on retries. Changing it requires a fresh output/checkpoint.

```sh
bfsort export ./repository --include-format pdf --naming detected --compression-level 0 -o ./pdfs.zip
```

Stored ZIPs can be larger, but avoid recompressing already-compressed content. Neither mode changes payload bytes or integrity requirements.
