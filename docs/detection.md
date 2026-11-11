# Content detection and mismatch reports

bfsort records content evidence independently of the filename. A mismatch is a
filename/content inconsistency, not a malware verdict. Detection never executes,
renders, follows links, or recursively extracts content. Permissions are not a sandbox.

## Stored fields and compatibility

Each occurrence retains its original name, final original extension, archive entry,
source provenance, SHA-256, size and identity. New `detection` metadata contains
`detected_family`, `detected_format`, optional `mime_type`, `confidence`, `evidence`,
`alternatives`, and `detector_version` (`bfsort-3`). New `mismatch` metadata contains
`status` and `reason`. Detection is performed before the staging handle is sealed
and published, using the prefix captured during the existing hash/copy pass.

`file_type` and `{file_type}` use the broad eight-category classifier and
meaning. They are intentionally independent of the stricter detailed detector:
for example an incomplete ELF prefix can retain legacy `file_type = "elf"` while
its detailed format is `unknown`. Use `detected_format` for precise content grouping.
Old records default to `not_evaluated` for detection and mismatch, never `match`.
Use a release compatible with the repository's SQLite schema.

Explicitly analyze an old **standard-mode** repository:

```sh
bfsort reclassify ./repository --resume
```

This hash-verifies each selected unique object, performs bounded classification and atomically updates SQLite classification metadata. Cancellation preserves the previous committed catalog values. Per-object checkpoints reuse detection with `--resume`; objects are still hash-verified. A new view is published using saved grouping rules; older views fall back to `by-format`.
Sealed repositories are refused; bfsort never changes payload permissions automatically.

## Supported identifiers and evidence

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

Confidence describes detection evidence, not safety:

- `high`: a strong signature with bounded header checks, a recognized shebang,
  or a supported ZIP directory structure.
- `medium`: a ZIP prefix without a validated bounded directory, a text structural
  preamble, complete JSON, or conflicting interpretations.
- `low`: printable UTF-8 without stronger evidence.
- `unknown`: no sufficient evidence, or a legacy unevaluated record.

PE requires DOS and PE headers with bounded offset and optional-header checks;
`MZ` alone is insufficient. ELF checks identification/header fields. Mach-O supports
thin and big-endian universal headers, with at most 64 architecture records. Java class files require a supported version (45–70) and a bounded constant pool (up to 4,096 slots), so shared magic alone is insufficient. PDF
headers are searched within the first 1 KiB. TAR checks the header checksum.
Script detection relies on recognized interpreters in shebangs; ordinary prose
and language-looking filenames do not establish a language. Batch/HTML/XML/JSON
use conservative preambles/parsing and medium confidence.

ZIP subtypes use central-directory names: OOXML requires `[Content_Types].xml`
and `word/document.xml`, `xl/workbook.xml` or `ppt/presentation.xml`; JAR requires
`META-INF/MANIFEST.MF`; APK requires `AndroidManifest.xml` and either `classes.dex`
or `resources.arsc`. An APK's JAR manifest is compatible, not a conflict. Conflicting
subtype markers produce `ambiguous` with alternatives. Container markers do not
validate document semantics or authenticity.

## Bounds and limitations

The fast path retains the existing 8 KiB prefix per worker. ZIP candidates
use additional reads through the already-open handle: at most a 65,557-byte tail
plus a 1 MiB directory, 4,096 entries and 4,096 bytes per name. Names are retained
only within those limits. No entry is decompressed during subtype detection.
This adds bounded transient directory/name allocations per ZIP worker, not a
separate full-file read. CFB candidates can additionally read at most 1 MiB of
allocation/directory metadata, at most 109 inline FAT sectors and 4,096 directory
entries, with loop and offset checks. Discriminating stream names identify DOC,
XLS and PPT; an installer root class identifier plus streams identifies MSI.
Conflicts are ambiguous. Encryption markers, external DIFAT chains, malformed
or over-budget metadata retain generic CFB. Stream content is not extracted.
Oversized, truncated, ZIP64 and multi-disk directories
remain generic ZIP. There is no mandatory new library, C runtime, external
executable or signature database; `infer` remains in the legacy classifier.

A signature is not full structural validation. Deeply embedded headers, binaries
with PE headers beyond the prefix, unsupported fat Mach-O variants, non-UTF-8 text without a supported UTF-16 BOM, or
truncated text, scripts without strong markers, and many polyglots can remain
unknown, generic or undetected. `ambiguous` covers observed conflicting headers
and subtype markers; it does not promise general polyglot discovery.

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
| `unknown_format` | Content evidence is insufficient |
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
