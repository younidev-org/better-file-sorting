# Configuration guide

[Documentation hub](README.md) · [Command reference](commands.md)

Runtime configuration and sorting rules are separate files. Pass runtime settings
with `-c/--config`; pass custom sorting rules with `--rules`. Commands that load
runtime configuration check `./bfs.toml` if no file is specified. Relative paths
resolve from the working directory. CLI values override configured grouping;
`--rules` replaces a configured preset and `--preset` replaces configured rules.
Unknown fields are rejected.

## Start with an example

| File | Purpose |
| --- | --- |
| [Local ingestion](../examples/config.example.toml) | Inputs, output, grouping and security |
| [Web collection](../examples/collection.example.toml) | Discovery, sealed downloads and subsequent ingestion |
| [Bounded processing](../examples/bounded.toml) | Explicit opt-in budgets and deadlines |
| [Archive rules](../examples/rules.example.toml) | Custom `.sample` naming and matching |
| [Regular-file rules](../examples/rules.files.example.toml) | Preserve ordinary filenames |

Built-in presets require no TOML:

```sh
bfsort export ./repository --preset by-format --zip-each-dir -o ./by-format
```

## Ingestion settings

```toml
inputs = ["incoming"]
output = "organized"
input_mode = "archives"
workers = 4
recursive = true
preset = "by-format"
resume = true

[security]
mode = "sealed"
```

`input_mode = "files"` is the default; ZIPs remain files unless archive mode or
CLI `--extract` is selected. The default repository is `organized/`, worker count
is available parallelism capped at eight, and recursion is enabled. Worker count
must be 1–256. Security defaults to sealed (`0000`); standard (`0600`) permits
payload exports. Private directories (`0700`) and no automatic unsealing are
mandatory safeguards. An existing repository's mode cannot change automatically.

`preset` accepts `by-format`, `by-format-or-extension`, `by-extension`, `by-mismatch`. Its omitted default
is `by-format`. Alternatively, `rules = "rules.toml"` selects custom rules.
Presets preserve all source occurrences. Custom rule duplicate policy is explicit
in `[organization]`. `resume = true` enables checkpoint reuse; CLI `--resume`
also enables it. Direct ZIP ingestion cannot resume; use a repository plus export.

Other root options: `password_file`, `zip`, `zip_dirs`, `zip_each_dir`,
`output_password_file`, `staging_dir`. See command help for equivalent flags.
Passwords are read from private `0600` files and are never stored in checkpoints.

## Optional budgets and timeouts

**Omitted application budgets and deadlines are unlimited.** This removes previous
implicit extraction caps and transfer deadlines. It does not prevent disk
exhaustion, metadata growth or stalled remote I/O. Use the bounded example for
explicit protection; it is never activated automatically.

For each resource budget or `timeout_seconds`:

| Value | Meaning |
| --- | --- |
| Omitted | Unlimited / no application deadline |
| `"unlimited"` | Explicitly unlimited |
| Positive integer | Bytes, count or seconds according to the field |
| Readable size string | Byte fields only, such as `"256 MiB"` |
| Zero, negative, malformed or overflowing value | Configuration error |

Byte units `KB`, `MB`, `GB` are decimal; `KiB`, `MiB`, `GiB` are binary. Fractions
are not accepted. Human output uses binary units; JSON byte values remain numeric.
The rule matcher size bounds are separate from budgets; a zero matcher bound is valid.

| Section | Optional settings |
| --- | --- |
| `[limits]` | `max_entry_bytes`, `max_archive_bytes`, `max_input_bytes`, `max_entries`, `max_expansion_ratio` |
| `[source]` | `max_page_size`, `timeout_seconds` |
| `[download]` | `max_files`, `max_file_size`, `max_total_size`, `max_staging_size`, `max_requests`, `timeout_seconds` |

Extraction byte/count limits and ratio checks apply only when configured. For
ordinary files, entry, archive and input byte budgets all apply to the copied file.
Download byte budgets include transferred failed bodies; staging budgets include
existing managed payloads. A timeout bounds request/pacing/body processing for
that operation. `source.timeout_seconds` controls discovery separately from
payload downloads. No application deadline is imposed when omitted. OS/library
network behavior still applies. Cancellation polls independently of deadlines;
see [recovery](recovery.md) for the network-worker limitation.

Technical checks remain mandatory: checked arithmetic, safe paths, metadata
record bounds, detector inspection bounds, supported archive structures, protected
password files, redirect-hop limits and integrity checks. Unlimited means no
application budget, not arbitrary allocations based on declared file sizes.

## Web acquisition

```toml
[source]
page = "https://example.org/downloads/"
same_origin = true

[download]
inventory = "collection/inventory.json"
staging_dir = "collection/downloads"
concurrency = 3
order_by = "source"
order = "ascending"
filename = "{original_name}"
```

Discovery accepts HTTP(S) URLs without credentials/query strings. Same-origin
restrictions and HTTPS downgrade refusal remain enforced. Concurrency is 1–256.
`directory` is a literal relative directory below `payloads/`; filename templates
are `{original_name}`, `{name}-{source_id}` or `{source_id}`. Duplicate destinations
fail before publication. `order_by` supports source order or name; `order` supports
ascending/descending. Include/exclude `[[download.policies]]` match resource names,
not the files inside archives; exclusions win.

`max_speed` is optional: positive bytes/s, `"2 MiB/s"`, or `"unlimited"`.
`min_request_interval_ms` defaults to zero (no spacing); this pacing setting can
be zero because it is not a resource budget. Request-count budgets apply separately to discovery and payload-download phases;
collect performs both phases. Receipt-verified completed downloads
are reused even without `--resume`; failed/incomplete bodies restart normally.

## Custom sorting rules

Rules use version `1`, an `[organization]` table and optional ordered `[[rules]]`.
Matchers within a rule all apply; first matching rule wins. Common settings:

- `filename_policy`: `samples` or `regular` (ordinary files only).
- `duplicates`: `first_only`, `all`, `only_duplicates`, `separate`.
- `view_mode`: `hardlink` or `manifest`.
- `default_directory` and `default_filename`: fallback templates.
- `[rules.match]`: `file_type`, `detected_format`, `mismatch_status`,
  `original_extension`, `encrypted`, `duplicate`, `min_size`, `max_size`.
- `[rules.output]`: replacement `directory` and `filename` templates.

The directory-only `{format_or_extension}` field enables automatic content grouping
with extension fallback, including in custom rules. See the [automatic rules
example](../examples/rules.automatic.example.toml).

Template fields include `detected_format`, `detected_family`, `mismatch_status`,
`original_extension`, `original_name`, `original_stem`, `file_type`, `sha256`,
`size`, `encrypted`, `duplicate`, `source_archive`, `ingest_date`, `occurrence_id`.
Custom rules retain their own fallback defaults; selecting a built-in preset
uses that preset's grouping instead. Archive-derived filenames must end in
`.sample`. Paths are sanitized and collisions receive deterministic suffixes.

## Nested ZIP extraction

Use [examples/nested.toml](../examples/nested.toml) for explicit depth and per-tree
limits. `nested_extraction = true` requires `input_mode = "archives"` and positive
`max_depth`. Disabled extraction requires zero depth. Tree budgets accept the same
positive integer/readable size/`"unlimited"` syntax as other limits; omitted budgets
are unlimited. See [nested extraction](nested.md) before processing large collections.

## Shared selection filters

`[filters]` selects stored occurrences or ingestion members independently of sorting
rules. See [repository selection](repository-tools.md#selection) and
[examples/filters.toml](../examples/filters.toml). Empty include lists allow all
values; matching exclusions win. A supplied CLI list replaces that TOML list.
Optional `sha256`, `mismatch`, `min_size` and `max_size` fields correspond to the
same CLI flags; sizes here are integer bytes with inclusive bounds. Unknown
fields/formats and reversed size ranges fail configuration validation.

Set `export_naming = "sample"`, `"original"` or `"detected"` in runtime configuration to choose ZIP payload suffixes; CLI `--naming` overrides it. Collection inventories default to `inventory.json`. Rediscover if the default inventory is missing.
