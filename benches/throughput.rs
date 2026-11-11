//! Benchmarks ingestion, resume, and view publication with disposable synthetic archives.

use bfsort::{
    app::config::{Config, Security, SecurityMode},
    ingest::pipeline,
    organization::organizer,
    organization::rules::Rules,
    repository::metadata,
    repository::storage::Repository,
};
use std::{fs::File, io::Write, sync::atomic::AtomicBool, time::Instant};
/// Run the end-to-end ingestion and organization benchmark matrix.
fn main() -> anyhow::Result<()> {
    if !cfg!(unix) {
        anyhow::bail!("storage benchmarks require the Unix permission backend");
    }
    let temp = tempfile::tempdir()?;
    let quick = std::env::var_os("BFS_BENCH_QUICK").is_some();
    for (scenario, archives, entries, bytes, random, duplicates) in [
        (
            "small",
            if quick { 100 } else { 10_000 },
            1,
            128,
            false,
            false,
        ),
        (
            "large-compressible",
            if quick { 4 } else { 100 },
            1,
            1024 * 1024,
            false,
            false,
        ),
        (
            "large-incompressible",
            if quick { 4 } else { 100 },
            1,
            1024 * 1024,
            true,
            false,
        ),
        (
            "many-entries",
            1,
            if quick { 100 } else { 10_000 },
            128,
            false,
            false,
        ),
        (
            "duplicates",
            if quick { 100 } else { 10_000 },
            1,
            128,
            false,
            true,
        ),
    ] {
        let input = temp.path().join(scenario);
        std::fs::create_dir(&input)?;
        let mut payload = vec![b'x'; bytes];
        if random {
            let mut state = 0x12345678u64;
            for byte in &mut payload {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
        }
        for archive in 0..archives {
            let mut zip =
                zip::ZipWriter::new(File::create(input.join(format!("{archive:05}.zip")))?);
            for entry in 0..entries {
                if !duplicates {
                    payload[..8]
                        .copy_from_slice(&((archive * entries + entry) as u64).to_le_bytes());
                }
                zip.start_file(
                    format!("{entry}.bin"),
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Deflated),
                )?;
                zip.write_all(&payload)?;
            }
            zip.finish()?;
        }
        for mode in [SecurityMode::Standard, SecurityMode::Sealed] {
            for workers in [1, 2, 4, 8, 16] {
                let output = temp
                    .path()
                    .join(format!("repo-{scenario}-{mode:?}-{workers}"));
                let mut config = Config {
                    input_mode: bfsort::app::config::InputMode::Archives,
                    inputs: vec![input.clone()],
                    output: output.clone(),
                    workers,
                    security: Security {
                        mode,
                        ..Security::default()
                    },
                    ..Config::default()
                };
                config.limits.max_expansion_ratio = Some(10_000);
                let start = Instant::now();
                let report = pipeline::ingest(&config, &AtomicBool::new(false))?;
                assert_eq!(report.accepted, archives * entries);
                assert_eq!(report.failures, 0);
                let seconds = start.elapsed().as_secs_f64();
                let repo = Repository::existing(&output)?;
                let load_start = Instant::now();
                let records = metadata::load(repo.root())?;
                let load_seconds = load_start.elapsed().as_secs_f64();
                let mut text = "[organization]\nduplicates = 'all'\n".to_string();
                for n in 0..100 {
                    text.push_str(&format!("[[rules]]\nname = 'rule-{n}'\n[rules.match]\nmin_size = {}\n[rules.output]\ndirectory = 'group-{n}'\nfilename = '{{sha256}}.sample'\n", 10_000_000 + n));
                }
                let rules = Rules::parse(&text)?;
                let reorganize_start = Instant::now();
                let plan = rules.plan(&records)?;
                organizer::organize(&repo, &rules, &plan)?;
                println!(
                    "{}",
                    serde_json::json!({ "scenario": scenario, "archives": archives, "entries": report.accepted, "workers": workers, "mode": mode, "seconds": seconds, "files_per_second": report.accepted as f64 / seconds, "mib_per_second": (report.accepted * bytes) as f64 / 1048576.0 / seconds, "metadata_load_seconds": load_seconds, "reorganize_seconds": reorganize_start.elapsed().as_secs_f64(), "stored_bytes": report.summary.stored_bytes, "allocated_bytes": report.summary.allocated_bytes })
                );
                drop(repo);
                config.resume = true;
                let setup_start = Instant::now();
                let setup = pipeline::ingest(&config, &AtomicBool::new(false))?;
                assert_eq!(setup.accepted, archives * entries);
                assert_eq!(setup.failures, 0);
                let setup_seconds = setup_start.elapsed().as_secs_f64();
                let resume_start = Instant::now();
                let resumed = pipeline::ingest(&config, &AtomicBool::new(false))?;
                assert_eq!(resumed.accepted, 0);
                assert_eq!(resumed.skipped_files, archives);
                assert_eq!(resumed.reused_occurrences, archives * entries);
                assert_eq!(resumed.failures, 0);
                println!(
                    "{}",
                    serde_json::json!({"scenario": scenario, "mode": mode, "workers": workers,
                    "resume_setup_seconds": setup_seconds, "resume_verify_seconds": resume_start.elapsed().as_secs_f64(),
                    "skipped_files": resumed.skipped_files, "reused_occurrences": resumed.reused_occurrences})
                );
                std::fs::remove_dir_all(output)?;
            }
        }
    }
    Ok(())
}
