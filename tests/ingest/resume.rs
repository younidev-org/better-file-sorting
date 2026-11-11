#![cfg(unix)]
use crate::common;
use bfsort::{
    app::config::{Config, InputMode, SecurityMode},
    ingest::pipeline,
};
use std::sync::atomic::AtomicBool;

fn config(input: &std::path::Path, output: &std::path::Path) -> Config {
    let mut config = Config {
        inputs: vec![input.into()],
        output: output.into(),
        input_mode: InputMode::Archives,
        ..Config::default()
    };
    config.security.mode = SecurityMode::Standard;
    config
}

#[test]
fn resume_skips_only_unchanged_complete_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.zip");
    common::archive(&input, &[("a.txt", b"hello")]);
    let mut config = config(&input, &dir.path().join("repo"));
    config.resume = true;
    let cancelled = AtomicBool::new(false);
    assert_eq!(pipeline::ingest(&config, &cancelled).unwrap().accepted, 1);
    let second = pipeline::ingest(&config, &cancelled).unwrap();
    assert_eq!(second.accepted, 0);
    assert_eq!(second.skipped_files, 1);
    assert_eq!(second.reused_occurrences, 1);
    common::archive(&input, &[("a.txt", b"world")]);
    let third = pipeline::ingest(&config, &cancelled).unwrap();
    assert_eq!(third.accepted, 1);
    assert_eq!(third.skipped_files, 0);
}

#[test]
fn resume_retries_failed_archive_without_duplicate_occurrences() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.zip");
    common::archive(
        &input,
        &[("a.txt", b"hello"), ("b.txt", b"a much longer item")],
    );
    let mut config = config(&input, &dir.path().join("repo"));
    config.resume = true;
    config.limits.max_entry_bytes = Some(5);
    let cancelled = AtomicBool::new(false);
    let first = pipeline::ingest(&config, &cancelled).unwrap();
    assert_eq!(first.failures, 1);
    config.limits.max_entry_bytes = None;
    let second = pipeline::ingest(&config, &cancelled).unwrap();
    assert_eq!(second.accepted, 2);
    assert_eq!(second.summary.occurrences, 2);
    assert_eq!(
        pipeline::ingest(&config, &cancelled).unwrap().skipped_files,
        1
    );
}

#[test]
fn resume_invalidates_limits_and_checks_canonical_content() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.zip");
    common::archive(&input, &[("a.txt", b"hello")]);
    let mut config = config(&input, &dir.path().join("repo"));
    config.resume = true;
    let cancelled = AtomicBool::new(false);
    pipeline::ingest(&config, &cancelled).unwrap();
    config.limits.max_entries = Some(10);
    assert_eq!(pipeline::ingest(&config, &cancelled).unwrap().accepted, 1);
    assert_eq!(
        pipeline::ingest(&config, &cancelled).unwrap().skipped_files,
        1
    );
    let hash = bfsort::repository::metadata::digest(b"hello");
    let object = config.output.join("objects").join(&hash[..2]).join(hash);
    std::fs::write(object, b"xxxxx").unwrap();
    let result = pipeline::ingest(&config, &cancelled).unwrap();
    assert_eq!(result.skipped_files, 0);
    assert_eq!(result.failures, 1);
}

#[test]
fn resume_sealed_objects_remain_sealed_and_direct_zip_is_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.zip");
    common::archive(&input, &[("a.txt", b"hello")]);
    let mut config = config(&input, &dir.path().join("repo"));
    config.resume = true;
    config.security.mode = SecurityMode::Sealed;
    let cancelled = AtomicBool::new(false);
    pipeline::ingest(&config, &cancelled).unwrap();
    assert_eq!(
        pipeline::ingest(&config, &cancelled).unwrap().skipped_files,
        1
    );
    let hash = bfsort::repository::metadata::digest(b"hello");
    let object = config.output.join("objects").join(&hash[..2]).join(hash);
    assert_eq!(
        std::fs::metadata(object).unwrap().permissions().mode() & 0o777,
        0
    );
    config.zip = true;
    assert!(
        pipeline::ingest(&config, &cancelled)
            .err()
            .unwrap()
            .to_string()
            .contains("persistent repository")
    );
}

#[test]
fn resume_regular_files_and_preview_leave_source_repository_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.txt");
    std::fs::write(&input, "hello").unwrap();
    let mut config = config(&input, &dir.path().join("repo"));
    config.input_mode = InputMode::Files;
    config.resume = true;
    let cancelled = AtomicBool::new(false);
    pipeline::ingest(&config, &cancelled).unwrap();
    let before = std::fs::read_dir(config.output.join("operations/ingest"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let state = std::fs::read(&before).unwrap();
    pipeline::preview(&config, &cancelled).unwrap();
    assert_eq!(state, std::fs::read(before).unwrap());
    assert_eq!(
        pipeline::ingest(&config, &cancelled).unwrap().skipped_files,
        1
    );
}

#[test]
fn encrypted_completed_input_skips_without_persisting_password_identity() {
    use std::{io::Write, os::unix::fs::PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("secret.zip");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&input).unwrap());
    zip.start_file(
        "a.txt",
        zip::write::SimpleFileOptions::default()
            .with_aes_encryption(zip::AesMode::Aes256, "fixture-secret"),
    )
    .unwrap();
    zip.write_all(b"hello").unwrap();
    zip.finish().unwrap();
    let passwords = dir.path().join("passwords");
    std::fs::write(&passwords, "fixture-secret\n").unwrap();
    std::fs::set_permissions(&passwords, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut config = config(&input, &dir.path().join("repo"));
    config.resume = true;
    config.password_file = Some(passwords.clone());
    let cancelled = AtomicBool::new(false);
    assert_eq!(pipeline::ingest(&config, &cancelled).unwrap().accepted, 1);
    std::fs::write(passwords, "different-password\n").unwrap();
    assert_eq!(
        pipeline::ingest(&config, &cancelled).unwrap().skipped_files,
        1
    );
    let path = std::fs::read_dir(config.output.join("operations/ingest"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let checkpoint = std::fs::read_to_string(path).unwrap();
    assert!(!checkpoint.contains("fixture-secret"));
    assert!(!checkpoint.contains(&bfsort::repository::metadata::digest(b"fixture-secret")));
}

#[test]
fn layout_changes_reuse_completed_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.zip");
    common::archive(&input, &[("a.txt", b"hello")]);
    let mut config = config(&input, &dir.path().join("repo"));
    config.resume = true;
    let cancelled = AtomicBool::new(false);
    pipeline::ingest(&config, &cancelled).unwrap();
    let rules = dir.path().join("rules.toml");
    std::fs::write(
        &rules,
        "[organization]\ndefault_directory = 'changed'\ndefault_filename = '{sha256}.sample'\n",
    )
    .unwrap();
    config.rules = Some(rules);
    let report = pipeline::ingest(&config, &cancelled).unwrap();
    assert_eq!(report.skipped_files, 1);
    assert_eq!(report.accepted, 0);
    let generation = std::fs::read_to_string(config.output.join("views/CURRENT")).unwrap();
    assert!(
        config
            .output
            .join("views")
            .join(generation.trim())
            .join("changed")
            .is_dir()
    );
}

#[test]
fn unsupported_checkpoint_version_fails_without_replacing_it() {
    let t = tempfile::tempdir().unwrap();
    let input = t.path().join("a.zip");
    common::archive(&input, &[("a", b"hello")]);
    let mut config = config(&input, &t.path().join("repo"));
    config.resume = true;
    pipeline::ingest(&config, &AtomicBool::new(false)).unwrap();
    let path = std::fs::read_dir(config.output.join("operations/ingest"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut checkpoint: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(checkpoint["schema_version"], 1);
    checkpoint["schema_version"] = 999.into();
    let bytes = serde_json::to_vec(&checkpoint).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let report = pipeline::ingest(&config, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.failures, 1);
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn large_ingest_checkpoint_and_report_remain_usable() {
    use bfsort::repository::{cleanup, verify};

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("large-metadata.zip");
    let long_extension = "x".repeat(60_000);
    // Distinct extensions make the report grow alongside the checkpoint's occurrence list.
    let names: Vec<_> = (0..150)
        .map(|index| format!("sample.{index}{long_extension}"))
        .collect();
    let entries: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), &b"hello"[..]))
        .collect();
    common::archive(&input, &entries);
    let mut config = config(&input, &dir.path().join("repo"));
    config.resume = true;
    let cancelled = AtomicBool::new(false);
    let report = pipeline::ingest(&config, &cancelled).unwrap();
    assert_eq!(report.accepted, names.len());
    assert_eq!(report.failures, 0);
    let checkpoint = std::fs::read_dir(config.output.join("operations/ingest"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert!(checkpoint.metadata().unwrap().len() > 16 * 1024 * 1024);
    let report_path = config
        .output
        .join("reports")
        .join(format!("{}.json", report.run_id));
    assert!(report_path.metadata().unwrap().len() > 16 * 1024 * 1024);

    let verified = verify::run(&config.output, true, &cancelled).unwrap();
    assert!(verified.failures.is_empty(), "{:?}", verified.failures);
    assert_eq!(verified.verified, 1);
    assert_eq!(
        cleanup::prune(&config.output, true, false)
            .unwrap()
            .candidate_objects,
        0
    );
    let resumed = pipeline::ingest(&config, &cancelled).unwrap();
    assert_eq!(resumed.reused_occurrences, names.len());
}
