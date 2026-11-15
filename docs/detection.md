# Content detection and mismatch reports

BFSORT runs the Linux `file --mime-type` command on staged content during
ingest and reclassification. Install `file` on PATH. Plain extraction with
`ingest --unzip-only` skips detection.

## Stored fields and compatibility

SQLite stores the MIME result alongside the original filename and extension.
The TOML registry supplies optional format and family aliases for filters,
reports, and extension mismatch checks. A specific MIME type such as
`image/svg+xml` appears in format groups and statistics even without a registry
entry. Generic results such as `application/octet-stream` group under
`undetected`. Results depend on the installed `file` version and magic database.

New detections record the backend as `linux-file-1`. Existing catalogs and JSON
records retain their fields. Reclassification refreshes detection from stored
payloads when an older catalog was classified by a different backend.

Explicitly analyze an old **standard-mode** repository:

```sh
bfsort reclassify ./repository --resume
```

This hash-verifies each selected unique object, runs `file` for classification and atomically updates SQLite classification metadata. Cancellation preserves the previous committed catalog values. Per-object checkpoints reuse detection with `--resume`; objects are still hash-verified. A new view is published using saved grouping rules; older views fall back to `by-format`.
Sealed repositories are refused; bfsort never changes payload permissions automatically.

## Format and family aliases

| Family | Format identifiers |
| --- | --- |
| executable | `pe`, `elf`, `macho`, `wasm`, `dex`, `java_class` |
| document | `pdf`, `rtf`, `cfb`, `doc`, `xls`, `ppt`, `docx`, `xlsx`, `pptx`, `html`, `xml`, `swf`, `lnk` |
| script | `javascript`, `powershell`, `python`, `shell`, `batch` |
| archive | `zip`, `rar`, `7z`, `tar`, `gzip`, `bzip2`, `xz`, `cab`, `zstd`, `lz4`, `ar` |
| package | `jar`, `apk`, `msi` |
| image | `png`, `jpeg`, `gif`, `webp`, `bmp`, `tiff` |
| database | `sqlite` |
| text | `json`, `text` |
| other states | `unknown`, `ambiguous`, `not_evaluated` |

Use `--include-format pdf` for an alias or `--include-mime image/svg+xml`
for a MIME type. The legacy `file_type` field remains available to custom rules.

## Extension compatibility

Normalization is case-insensitive, ignores leading dots, and uses the final
extension. `.tar.gz`, `.tar.bz2`, and `.tar.xz` are recognized as compound suffixes
for evaluation and statistics; the unmodified final extension remains in metadata.
Double extensions have no independent verdict: `invoice.exe.pdf` is checked as
PDF, and `document.pdf.exe` as EXE.

The registry includes EXE/DLL/SYS/SCR/OCX/CPL → PE; ELF/SO → ELF; DYLIB/MACHO →
Mach-O; DOC/XLS/PPT/MSI → their detected CFB subtypes (generic CFB is ambiguous); DOCX/DOCM, XLSX/XLSM, PPTX/PPTM → the respective
OOXML family; JS/MJS/CJS → JavaScript; PS1/PSM1 → PowerShell; PY → Python;
SH/BASH/ZSH → shell; BAT/CMD → batch; HTML/HTM → HTML; XML/SVG → XML;
JSON → JSON; TXT/LOG/CSV/MD → text. Archive aliases include GZ/TGZ/TAR.GZ,
BZ2/TBZ2/TAR.BZ2 and XZ/TXZ/TAR.XZ. Image aliases include JPG/JPEG/JPE and
TIF/TIFF. SQLite accepts SQLITE/SQLITE3/DB. PDF/RTF/ZIP/RAR/7Z/TAR/JAR/APK/PNG/GIF/WEBP/BMP/WASM
use their named suffixes. Unlisted suffixes remain unknown.

| Status | Meaning |
| --- | --- |
| `match` | Registered extension agrees with identified format (EXE and DLL both match PE) |
| `compatible` | Generic BIN/DAT/TMP, or a ZIP extension on a recognized ZIP subtype |
| `mismatch` | High-confidence evidence contradicts a recognized extension |
| `missing_extension` | Filename has no extension |
| `unknown_extension` | Extension is not registered |
| `unknown_format` | There is no format alias for an extension comparison |
| `ambiguous` | Conflicting interpretations, generic ZIP against a subtype extension, or evidence too weak to contradict the extension |
| `not_evaluated` | Legacy metadata not yet analyzed |

Generic text with `.js` is ambiguous; generic ZIP with `.docx` is ambiguous.
Neither produces a definitive mismatch. Extensionless files have their own status.

## Reports and statistics

```sh
bfsort report mismatches ./repository
bfsort report mismatches ./repository --format csv --output mismatches.csv
bfsort report mismatches ./repository --format json --output mismatches.json
bfsort report mismatches ./repository --format json --all
bfsort report mismatches ./repository --status mismatch,ambiguous --min-confidence medium
bfsort stats ./repository --json
```

Reports default to definitive mismatches. `--all` includes every status; explicit
`--status` (repeatable or comma-separated) takes precedence. Confidence filtering
applies to rows. Status counts cover **all** occurrences before row filtering.
Table and JSON include those counts; CSV contains selected rows only.
`--json` changes the default table to JSON; an explicit non-table format wins.
`--quiet` suppresses stdout, while `--output` still writes the requested artifact.
Output files are created atomically and never replace an existing destination.

JSON contains `counts` and `rows`. Each row has
SHA-256, occurrence ID, source archive, original entry name/extension, detected
family/format, MIME, confidence, mismatch status/reason, detector version. CSV
quotes every data field and doubles embedded quotes; JSON uses serde serialization.
When importing untrusted CSV into spreadsheet software, import filename/source
columns as text so spreadsheet software does not interpret them as formulas.
Terminal output escapes control characters. Rows are sorted deterministically.

Statistics preserve all existing fields and add `by_detected_family`,
`by_detected_format`, `by_original_extension`, `by_mismatch_status`,
`extension_format`, and `mismatch_pairs`. Each bucket has `occurrences` and
`unique_hashes`. Cross tables are sparse extension/format rows, ordered by key;
`mismatch_pairs` contains definitive mismatch pairs. Unknown and ambiguous counts
are explicit buckets. One hash can occur under multiple extensions and statuses,
so summing unique counts across those buckets may exceed global unique samples.
Reports evaluate every occurrence before duplicate policies select exported files.

## Ingest once, export several views

For payload ZIP exports, create a standard repository explicitly:

```sh
bfsort ingest ./incoming --extract --security-mode standard --output ./repository
bfsort export ./repository --rules examples/rules.formats.example.toml --zip-each-dir --output ./by-format
bfsort export ./repository --rules examples/rules.extensions.example.toml --zip-each-dir --output ./by-extension
bfsort export ./repository --rules examples/rules.formats.example.toml --output ./all-formats.zip
bfsort export ./repository --rules examples/rules.formats.example.toml --zip-each-dir --output ./preview --dry-run
```

`export` loads existing objects and metadata. It never opens original daily ZIPs,
re-extracts, rehashes, reclassifies, or changes the repository's view pointer.
It reuses duplicate policies, safe path planning, ZIP directory selection and
atomic no-replace publication. `--zip-dir` and `--output-password-file` also work
as for ingestion. Parent output directories must already exist. Standard-mode
payload permissions are checked before opening each object. Export trusts stored
object identities and metadata; it does not perform an integrity audit.

Sealed repositories support metadata reports, `reorganize` and `export --dry-run`,
but payload export and analysis are refused. Existing objects and exports remain
unchanged when another view is exported. Archive-derived files keep `.sample`
names even if a rule attempts to select the regular filename policy.

Use `{detected_format}`, `{detected_family}`, or `{mismatch_status}` in templates,
and `detected_format` / `mismatch_status` in `[rules.match]`. Existing `{file_type}`
and `{original_extension}` templates retain their meanings. Legacy records sort
under `not_evaluated` until explicit analysis. Use `duplicates = "all"` when a
view must preserve every distinct source occurrence and filename association.

## Built-in presets and recovery

`by-format` is the default grouping; `by-extension` uses original suffixes and
`by-mismatch` uses filename/content agreement. Presets preserve every occurrence
and are mutually exclusive with custom `--rules`. See [exports](exports.md) for
the portable ZIP manifest and [recovery](recovery.md) for `--resume` verification.
Omitted extraction budgets are unlimited; the detector bounds above remain
mandatory technical limits. Use [bounded configuration](../examples/bounded.toml)
to opt into resource budgets.

## Additional header formats

DEX versions 035 and 037–040 require the 112-byte little-endian header and bounded
section declarations; experimental containers and reverse-endian DEX remain
unknown. CAB version 1.3 requires consistent header/size bounds. Zstandard checks
frame descriptor and first block header; LZ4 checks frame flags and descriptor
checksum. Skippable-only frames remain unknown. ar requires a valid first member
header. SWF supports FWS/CWS/ZWS header checks without decompressing content.
Shell links require the 76-byte header, class identifier and reserved fields.
These checks identify formats, not full-file validity or safe content.

UTF-16LE/BE BOM text uses the same conservative text/script rules as UTF-8.
New suffix mappings include DEX, CLASS, CAB, ZST/ZSTD, LZ4, AR/A/LIB, SWF and LNK.
Format recognition does not add extraction backends: recursive extraction remains
ZIP-only, including recognized ZIP-backed packages and documents.

Format references used for bounded checks:

- [Android DEX specification](https://source.android.com/docs/core/runtime/dex-format)
- [Java class-file specification](https://docs.oracle.com/en/java/javase/26/docs/specs/jvms/jvms-4.html)
- [Apple universal Mach-O headers](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/fat.h)
- [Microsoft Cabinet specification](https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/%5Bms-cab%5D.pdf)
- [Zstandard frame specification](https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md)
- [LZ4 frame specification](https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md)
- [Microsoft CFB specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/)
- [Microsoft Shell Link specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/)
- [Adobe SWF specification](https://www.adobe.com/content/dam/acom/en/devnet/pdf/swf-file-format-spec.pdf)
