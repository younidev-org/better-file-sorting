# Reproducible derived datasets

`sample`, `split`, and `merge` build independent repositories. Payloads remain SHA-256-addressed files; SQLite stores their metadata. These commands preserve original provenance and effective classifications.

```sh
bfsort sample SOURCE --count 100 --seed 7 -o SAMPLE
bfsort sample SOURCE --percentage 10 --stratify ingest-date,family --seed 7 -o SAMPLE
bfsort sample SOURCE --count 100 --unit occurrence --seed 7 -o SAMPLE
bfsort split SOURCE --by format -o PARTITIONS
bfsort merge LEFT RIGHT -o MERGED
```

Filters apply before sampling or partitioning. Supply exactly one of `--count` and `--percentage`. Counts cannot exceed the eligible population; percentages must be finite and between zero and 100. Percentage targets round down. Zero is valid and produces an empty dataset.

The default sampling unit is `unique-hash`: duplicate content gets one chance, represented by its smallest occurrence ID. This representative supplies the original provenance and stratification fields. Use `--unit occurrence` to sample distinct source events, allowing multiple records with the same bytes. Selecting a hash does not import every duplicate occurrence automatically.

`--stratify ingest-date,family` groups eligible sampling units by stored ingestion date and detected format family. This family describes file formats, not malware families. No collection date is inferred. Allocation is proportional: take each stratum's floor quota, then award remaining positions by descending fractional remainder, breaking ties by the ordered stratum values. Within each stratum, rank ascending SHA-256 over `bfsort-dataset-v3`, a zero byte, the unsigned 64-bit big-endian seed, and the ASCII sampling identity (hash or occurrence ID). Rank ties use occurrence ID. Unchanged metadata, filters, settings and seed reproduce the same selection.

Each final repository contains `reports/dataset.json`. The report records schema and algorithm versions, canonical source paths and metadata snapshot fingerprints, filters, sample settings and allocations, sorted selected visible occurrence IDs and hashes, explicit ancestry occurrence IDs and hashes, and detector versions. Physical object/byte estimates include structural ancestry; ancestry additions count extra records per destination partition. It describes how the dataset was produced; it does not pin payloads against pruning. Split writes one report inside each partition repository. Its container report aggregates roles across partitions: a parent may be selected in one partition and structural in another. The enclosing split directory is a container, not a repository.

Extension groups use lowercase original extensions encoded as `ext-` plus hexadecimal UTF-8 bytes (`txt` becomes `ext-747874`); an absent extension uses `unknown`. Format groups use the existing detected-format enum, including unknown and not-evaluated values. Nested selections retain every stored ZIP ancestor needed by their provenance. Additional ancestors are marked structural and hidden from default queries and sample counts; selected visible parents stay visible. Each split partition receives its own closure. Missing, conflicting, non-ZIP, cyclic or removed ancestors fail closed. An outer input referenced without a parent occurrence ID is external provenance and does not require an invented record. Sealed repositories permit metadata-only dry-runs; actual copies require standard sources and never change source security modes.

## Resume

Add `--resume` on the first run and subsequent retries:

```sh
bfsort sample SOURCE --count 100 --seed 7 -o SAMPLE --resume
```

Resume keeps a private sibling directory named `.bfsort-dataset-<SHA256 of canonical destination>`. It holds a SQLite checkpoint, an operation lock and the unpublished result tree. Cancellation or a failed copy retains this directory. A later run must match the complete effective source metadata snapshots, filters, seed, algorithm and grouping settings. Changed settings or sources fail rather than mixing datasets.

Completed staged objects are size-checked and hashed before reuse; corrupt objects cause failure. Metadata is stored only after its object is durable. Publication atomically refuses an existing destination. If publication succeeded before the caller observed completion, repeating the same resumable command validates the final report, metadata and payload hashes and reports reused objects. Resume checkpoints remain available after successful publication for that validation.

Without `--resume`, temporary staging is cleaned up on normal failure or cancellation. Abrupt process termination can leave private staging. Dry-run creates neither a result nor a resume checkpoint. Destination parents must already exist. Source aliases and overlapping paths are rejected, source locks are acquired in canonical order, and objects are copied rather than hardlinked across repositories. There is no automatic repair of corrupt staged data or silent overwrite of a destination.
