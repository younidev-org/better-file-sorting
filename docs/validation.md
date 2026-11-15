# Reliability, security and performance

[Documentation hub](README.md) · [Command reference](commands.md)

## Supported platform

bfsort supports Linux. Repository storage requires Unix permissions; unsupported
storage platforms fail explicitly. No Windows or macOS executables are distributed.

## File handling

bfsort streams inputs into private temporary storage while computing SHA-256 and
checking configured size and expansion limits. Archive paths, entry kinds,
passwords and integrity checks are validated before publication. Stored objects
are deduplicated by hash; occurrence metadata preserves distinct source names
and provenance.

Sealed payloads have no permission bits (`0000`). Standard payloads use `0600`,
and managed directories use `0700`. bfsort never automatically unlocks an existing
payload. Permissions are not a sandbox: the owner or root can change them.
Use an isolated environment when handling untrusted content.

ZIP exports and report files refuse to overwrite existing destinations. View
reorganization retains previous generations. Interrupted ingestion can leave
private staging data, which subsequent ingestion recovers under the repository
lock. Existing source files remain untouched.

## Detection and reports

Content detection uses bounded signatures, header checks and ZIP directory
markers. It does not execute files, render documents or establish whether a file
is safe. A mismatch means that a recognized filename extension contradicts
strong content evidence.

Unknown, ambiguous and unevaluated records remain explicit. Metadata-only reports
work on sealed repositories. Payload exports and explicit analysis require a
standard repository. Export trusts stored identities and classification metadata;
it does not rehash objects or perform an integrity audit.

See [content detection](detection.md) for supported formats, compatibility
mappings, inspection limits and report examples. CSV preserves raw source values;
import untrusted filename columns as text in spreadsheet software.

## Performance

Worker count, file sizes, compression, duplicate frequency and filesystem latency
all affect throughput. More workers do not always improve performance. The
detector reuses the 8 KiB prefix captured during hashing; ZIP and CFB candidates
require additional bounded metadata reads. Repository-wide reports retain
metadata in memory, so memory use grows with collection size.

The benchmark harness uses synthetic benign inputs. Its timings depend on the machine and dataset.

The ingestion comparison covers five workloads, five worker counts and both
security modes. Quick-mode workloads use 100 small or duplicate archives, one
archive with 100 entries, or four 1 MiB archives. Results vary in both directions;
the small in-memory detector benchmark does not predict end-to-end throughput.

## Developer checks

To verify a local build:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo nextest run --locked
```

Some integration tests start local HTTP servers. `nextest` is optional.
To measure synthetic performance:

```sh
cargo bench --locked --bench detection
BFS_BENCH_QUICK=1 cargo bench --locked --bench throughput
```

Omit `BFS_BENCH_QUICK` for larger workloads. The fuzz harness requires nightly
Rust and cargo-fuzz:

```sh
cargo +nightly fuzz run untrusted_inputs -- -max_total_time=30 -max_len=65536
```

Tests and short fuzz runs cannot establish complete parser correctness, universal
classification accuracy or resilience to every filesystem failure.

## Recovery and resource checks

The regression suite covers complete-input reuse, changed input/settings,
view-only changes, encrypted inputs, standard-object corruption, sealed access,
partial archive retry and checkpoint schema rejection. Export tests cover the
portable manifest, all presets, missing output recovery, changed plans, tampered
ZIPs and the publication-before-receipt crash window, including both metadata
indexes. Source/password files remain unchanged.

Controlled fixtures exercise a streamed file larger than 256 MiB, a sparse ZIP
larger than 1 GiB, more than 10,000 entries, and expansion beyond previous default
budgets. Explicit caps still reject oversized work. Local HTTP fixtures cover
optional deadlines and cancellation of a stalled body. Terminal checks cover
independent stdout/stderr color detection, NO_COLOR, plain CSV errors and labels
that do not style untrusted paths as status text.

The comparison uses the same synthetic five-workload, five-worker-count,
standard/sealed matrix. Each normal and resume matrix has 50 cases. Resume setup
processes the input with checkpoints; verified resume must accept zero new
occurrences and report all input files skipped. Input verification still reads
archive bytes, and standard stored objects are hash-verified. Results are single
shared-host runs, not statistical performance guarantees or large real-dataset
accuracy measurements. Timings can vary in either direction with workload.

AddressSanitizer smoke fuzzing exercises untrusted detection, names, metadata and
report serialization. Leak detection is disabled for this environment. A short
fuzz run does not establish exhaustive parser correctness. These checks do not
prove power-loss durability, arbitrary OOM recovery or immediate OS socket closure.
Discovery parses HTML in memory, and repository/checkpoint metadata grows with
collection size; unlimited budgets do not imply constant memory usage.

## Nested extraction qualification

The reproducible harness is `benches/nested.py`. Supply a v0.7.0 baseline binary
and the candidate release binary:

```sh
python3 benches/nested.py /path/to/v0.7.0/bfsort ./target/release/bfsort
```

The measurements below use seed 12345, one warm-up and five
measured runs, one worker and a warm OS cache. Many-small uses 1,000 files of
1 KiB; few-large uses four files of 8 MiB. Each run has a separate repository.
The harness records wall time, peak RSS, and sampled staging-file size at 5 ms
intervals. Sampled staging sizes are lower bounds, not guaranteed high-water marks.

| Case | Baseline median | Candidate median | Candidate/baseline |
| --- | ---: | ---: | ---: |
| Many small, fresh | 0.1740 s | 0.1777 s | 1.021 |
| Many small, resume | 0.3083 s | 0.3046 s | 0.988 |
| Few large, fresh | 0.0867 s | 0.0880 s | 1.014 |
| Few large, resume | 0.0521 s | 0.0522 s | 1.002 |

All four ratios pass the planned 1.10 ceiling. These subsecond synthetic results
are not throughput guarantees for a 129 GiB malware repository.

The nested fixture contains ten identical ZIP occurrences with a nested leaf ZIP.
Depth-1/depth-2 fresh runs decompressed two/three unique archives respectively.
Completed resume decompressed zero; removing one receipt from a disposable fixture
required exactly one fresh extraction. That receipt-removal case tests missing
checkpoint recovery, not arbitrary power-loss durability. A separate password-retry
regression verifies successful siblings are reused after an incomplete branch.

Depth-2 fresh ingestion measured a 0.0646 s median; existing-repository expansion
measured 0.0468 s for the same final content/occurrence counts. Depth-2 completed
resume measured 0.0903 s: repeated integrity verification can cost more than fresh
decompression on this small duplicate-heavy input. No universal resume speedup is
claimed. Reclassification performed no archive extraction.

Independent review found descriptor accumulation in sealed traversal, missing
budget preflight, missing tree checkpoint identity, and a truncated CAB false
positive. Each received a failing regression test followed by a passing fix.
Qualification passed 159 tests, formatting, Clippy with warnings denied, and a
release build. The example nested configuration validates.

An attempted AddressSanitizer fuzz smoke did not run: the existing generated
build cache was invalid, and a clean rebuild encountered compiler-cache permission
and disk-quota failures. No new sanitizer coverage is claimed. Real-dataset scale,
forced power-loss injection and non-Linux platforms were not qualified.
