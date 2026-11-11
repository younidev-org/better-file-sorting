# Command reference

[Documentation hub](README.md) · [Configuration](configuration.md)

Run `bfsort --help` or `bfsort COMMAND --help` for every accepted option.
The primary workflow is:

```text
collect → ingest --extract → stats/report → export
```

`collection/` contains downloaded input archives. `organized/` is an ingested
repository. Repository commands cannot read a download folder as a repository.
The former `organize` alias is removed; use `ingest`.

## Output controls

`--color auto|always|never` controls human terminal styling. Auto detects each
stream independently. `NO_COLOR` disables auto color; `--no-color` overrides an
explicit color selection. Cyan denotes headings/progress, green completion,
yellow partial results, and red errors. Text labels carry the same meaning
without color. Progress uses one shared line on interactive stderr.
Known totals show completed work, percentage, and elapsed time. Unknown work uses
a spinner with elapsed time. `--no-progress` hides loading indicators while retaining final results.

`--json` writes machine-readable results without color or progress.
JSON/CSV mismatch formats never contain styling. `--quiet` suppresses
normal output, not errors. `--verbose` shows effective configuration, paths,
workers, resource budgets and deadlines without exposing passwords.

Human sizes use binary units (KiB, MiB, GiB); machine byte counts stay numeric.
Exit status is `0` for success, `1` for failure without accepted/reused work, and
`2` for partially successful ingestion. Export errors return `1`; a resumable
export can retain completed ZIPs while its collection remains incomplete.

## Download archives

```sh
bfsort collect https://example.org/downloads/ -o ./collection
bfsort collect -c collection.toml --resume
```

Collect discovers when inventory is missing, then downloads selected ZIPs.
`--refresh` repeats discovery. It does not ingest or automatically unlock files.
Download payloads are sealed; explicit authorized access is required before
subsequent ingestion. See [security and reliability](validation.md).

For separate acquisition steps:

```sh
bfsort discover https://example.org/downloads/
bfsort download --dry-run
bfsort download --resume
```

Both normal download and `--resume` reuse validated completion receipts. Missing
or failed downloads are retried; incomplete HTTP bodies restart from the beginning.
Existing unreceipted files are never silently replaced. `collect --dry-run` may
request HTML when inventory is absent; it never downloads payloads or writes
acquisition state. `download --dry-run` selects from saved inventory offline.

## Ingest files or ZIP contents

```sh
bfsort ingest ./documents -o ./organized
bfsort ingest ./incoming --extract -o ./repository --security-mode standard --resume
bfsort ingest -c collection.toml --resume
```

Ordinary files are the default. ZIP files stay intact unless `--extract` or
`--input-mode archives` is selected. Without explicit inputs, configured completed
download receipts are used; otherwise the fallback directory is `incoming/`.

Repository security defaults to `sealed` (`0000` payload permissions). Select
`--security-mode standard` (`0600`) before ingestion if you need payload exports
or explicit analysis. Existing repository security modes never change automatically.
These permissions are not a sandbox.

Grouping defaults to `--preset by-format`. Choose `by-format-or-extension`, `by-extension` or `by-mismatch`,
or supply custom `--rules FILE`. Presets and custom rules are mutually exclusive.
Presets retain every distinct occurrence; custom rules control duplicate policy.
Archive-derived filenames remain safe `.sample` names. `--workers N` selects
1–256 workers; `--recursive false` excludes nested input folders.
`--password-file FILE` reads input archive passwords from a private `0600` file.

`--resume` skips verified complete input archives/files. Verification rereads
input bytes, and standard-mode stored objects are hash-verified. It skips
extraction/classification, not all disk I/O. Changed processing settings or input
content trigger reprocessing; changing grouping only rebuilds the view.
Interrupted/failed archives retry from the beginning, not an arbitrary entry.
See [recovery](recovery.md).

`--dry-run` previews layout by reading/hashing inputs in disposable private
storage. It publishes no repository, output ZIP or durable resume checkpoint.
It can require archive passwords and substantial temporary disk space.

## Extract ZIPs without repository metadata

```sh
bfsort ingest --unzip-only ./incoming -o ./extracted
bfsort ingest --unzip-only -c ./ingest.toml --security-mode standard -o ./extracted
```

`--unzip-only` extracts regular files and directories with their archive paths.
A single ZIP extracts directly into the destination. Multiple ZIPs each get a
directory named after the ZIP's filename stem. Choose a destination that does
not exist. Path, password, integrity, and extraction-limit checks still apply.

The destination is published after every ZIP succeeds. Output files default to
sealed permissions (`0000`); use `--security-mode standard` for readable
owner-only files (`0600`). Nested ZIP entries are kept as files. Extraction-only
runs do not classify files or create a repository or resume checkpoint.

## Direct ZIP output

```sh
bfsort ingest ./incoming --extract --zip -o ./sorted.zip
bfsort ingest ./incoming --extract --zip-each-dir --preset by-format -o ./by-format
```

Direct ZIP output uses a disposable private standard repository. It removes
temporary unpacked data after successful processing and leaves input archives
untouched. It cannot resume: for recoverable large collections, ingest into a
persistent repository first, then export with `--resume`.

`--zip-dir DIRECTORY` selects sorted directories; repeat to choose several.
`--zip-each-dir` creates one ZIP per selected directory, or per top-level group.
Automatic fallback grouping uses each full group directory, producing
`detected/pdf.zip` and separate `undetected/extension-*.zip` files.
`--output-password-file FILE` encrypts output with AES-256; the private `0600`
file must contain exactly one nonempty password line. `--staging-dir DIRECTORY`
selects an existing scratch directory. Output destinations are never overwritten.
Temporary plaintext can survive forced termination; choose storage accordingly.

## Inspect, summarize and report

```sh
bfsort inspect ./incoming
bfsort stats ./repository
bfsort stats ./repository --json
bfsort report mismatches ./repository
bfsort report mismatches ./repository --format csv -o ./mismatches.csv
bfsort report mismatches ./repository --format json --all
bfsort report mismatches ./repository --status mismatch,ambiguous --min-confidence medium
```

Inspect reads ZIP entry metadata without extracting payloads. Stats reads repository
metadata and filesystem usage without opening payload contents. Its human summary
distinguishes unique samples, occurrences and duplicate occurrences.

Mismatch reports default to definitive mismatches. `--all` includes every status;
explicit `--status` takes precedence. `--min-confidence` filters rows. Table and
JSON include counts before filtering; CSV contains selected rows only.
`--output` writes atomically without replacing an existing file, even in quiet
mode. A mismatch is not a malware verdict. See [detection](detection.md).

## Export stored collections

```sh
bfsort export ./repository --preset by-format --zip-each-dir -o ./exports/by-format --resume
bfsort export ./repository --preset by-extension --zip-each-dir -o ./exports/by-extension --resume
bfsort export ./repository --preset by-mismatch --zip-each-dir -o ./exports/by-mismatch --resume
bfsort export ./repository -o ./all.zip
```

Export requires standard payloads; sealed repositories support `--dry-run` only.
It reuses saved classification and never re-extracts original inputs or
reclassifies samples. Normal output is published atomically without replacing
destinations. Resumable multi-ZIP output publishes each verified archive separately;
a partial collection can contain completed ZIPs. See [exports](exports.md) for
portable metadata and [recovery](recovery.md) for verification costs.

## Rebuild views or refresh analysis

```sh
bfsort reorganize ./repository --preset by-extension --dry-run
bfsort reorganize ./repository --rules ./rules.toml
bfsort reclassify ./repository --resume
bfsort analyze ./repository -c ./examples/nested.toml --dry-run
bfsort analyze ./repository -c ./examples/nested.toml --resume
```

Reorganize adds a new view generation without extracting or reading payloads;
old generations remain available. `reclassify` verifies and detects each unique
stored object, atomically updates SQLite classifications, and rebuilds the view
using its saved rules (older views without saved rules use `by-format`). Its
`--resume` option reuses per-object detection checkpoints; `--dry-run` lists the
unique-object count and detector version without writing.

`analyze` expands supported ZIP objects already stored in a **standard-mode**
repository. Original downloads are unnecessary. It preserves original records
and adds child occurrences with parent links. Analysis depth starts at each
existing archive occurrence, independently from its historical outer download.
`--dry-run` previews candidates, reusable direct extraction receipts and limits;
expanded sizes remain unknown. Repeated analysis is idempotent. Completed direct
extractions are always cached; `--resume` documents intent to continue previous
work and is also accepted for consistency with ingestion.

Neither operation changes stored sample bytes or unlocks sealed payloads.
Unsupported schemas fail explicitly. See [nested extraction](nested.md) for
configuration, depth examples, budgets and failure behavior.

Automatic grouping with extension fallback is available through
`--preset by-format-or-extension`. Custom rules can use `{format_or_extension}`
as their default directory and override selected formats or extensions. See
[presets and exports](exports.md#automatic-grouping-with-optional-explicit-rules).

## Configuration validation

```sh
bfsort config validate -c ./examples/config.example.toml
```

Commands loading runtime configuration use `-c/--config FILE`, otherwise check
`./bfs.toml` in the current directory. Relative paths resolve from the working
directory. Unknown settings and malformed or zero resource budgets are rejected.
Omitted optional budgets and deadlines are unlimited; see [configuration](configuration.md).

## Repository management and queries

```sh
bfsort query ./repository --include-format pdf --count
bfsort query ./repository --mismatch mismatch --min-size 1024 --json
bfsort verify ./repository --full
bfsort diff ./repository ./other
bfsort sample ./repository --count 100 --seed 42 -o ./sampled
bfsort split ./repository --by format -o ./parts
bfsort merge ./repository ./other -o ./merged
bfsort status ./repository --json
bfsort retry ./repository --operation OPERATION_ID
bfsort remove ./repository --include-ext exe --dry-run
bfsort remove ./repository --include-ext exe --confirm
bfsort prune ./repository --dry-run
```

See [repository tools](repository-tools.md) for independent-copy guarantees,
selection semantics, recovery history, and cleanup safeguards. `prune --confirm`
reclaims only canonical objects with no recognized retained reference; removing
an occurrence does not automatically reclaim its payload.

## SQLite metadata

```sh
bfsort metadata import ./repository ./source/metadata.sqlite3
```

Repository commands require a schema v3 `metadata.sqlite3`. Re-ingest older repositories
from the original inputs into a fresh directory. Import reads active occurrences from a v3 catalog
and requires the referenced objects in the destination. See
[SQLite metadata](sqlite.md) for backup, schema, privacy and recovery details.

Sample by percentage with `sample REPOSITORY --percentage 10 --stratify ingest-date,family --seed 7 -o SAMPLE`. The default unit is unique content hashes; `--unit occurrence` samples source events. Merge, split and sample accept `--resume`. See [datasets](datasets.md).

Analyze and reclassify accept shared selection flags. Ingest and export accept `--naming sample|original|detected`; see [exports](exports.md). Reports support table, JSON and CSV.
