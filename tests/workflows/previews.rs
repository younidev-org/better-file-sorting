// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Preview and publication parity, failure cleanup, and ZIP size reporting.

#![cfg(unix)]
use crate::common;
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn zip_failure_identifies_source_and_cause() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("oversize.txt");
    fs::write(&input, b"too large").unwrap();
    let config = dir.path().join("config.toml");
    fs::write(
        &config,
        "input_mode = 'files'\nzip = true\n[limits]\nmax_entry_bytes = 2\n",
    )
    .unwrap();
    let output = dir.path().join("out.zip");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--config".as_ref(),
        config.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
    ]);
    assert!(!out.status.success());
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(
        error.contains("oversize.txt") && error.contains("file size limit exceeded"),
        "{error}"
    );
    assert!(!output.exists());
}

#[test]
fn preview_matches_actual_layout_including_duplicates_and_existing_records() {
    let dir = tempfile::tempdir().unwrap();
    let inputs = dir.path().join("inputs");
    fs::create_dir_all(inputs.join("nested")).unwrap();
    fs::write(inputs.join("a.txt"), b"one").unwrap();
    fs::write(inputs.join("nested/a.txt"), b"two").unwrap();
    fs::write(inputs.join("duplicate.txt"), b"one").unwrap();
    let rules = dir.path().join("rules.toml");
    fs::write(
        &rules,
        "[organization]\ndefault_filename = '{original_name}.sample'\n",
    )
    .unwrap();
    let repo = dir.path().join("repo");
    let args = [
        "ingest".as_ref(),
        inputs.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "--output".as_ref(),
        repo.as_os_str(),
        "--rules".as_ref(),
        rules.as_os_str(),
    ];
    let mut preview_args = args.to_vec();
    preview_args.push("--dry-run".as_ref());
    let out = common::run(&preview_args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(preview["summary"]["duplicate_occurrences"], 1);
    assert_eq!(preview["plan"].as_array().unwrap().len(), 2);
    assert!(
        preview["plan"][0]["source_path"]
            .as_str()
            .unwrap()
            .contains("a.txt")
    );
    assert!(!repo.exists());
    let out = common::run(&args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let current = fs::read_to_string(repo.join("views/CURRENT")).unwrap();
    let actual = bfsort::repository::catalog::read(&repo)
        .unwrap()
        .view_plan(current.trim())
        .unwrap();
    assert_eq!(actual.len(), preview["plan"].as_array().unwrap().len());
    for planned in preview["plan"].as_array().unwrap() {
        let row = actual
            .iter()
            .find(|r| r.occurrence_id == planned["occurrence_id"].as_str().unwrap())
            .unwrap();
        assert_eq!(planned["path"], row.path);
        assert_eq!(planned["sha256"], row.sha256);
    }
    fs::remove_file(inputs.join("nested/a.txt")).unwrap();
    let out = common::run(&preview_args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        preview["plan"].as_array().unwrap().len(),
        2,
        "existing repository records missing"
    );
    assert_eq!(
        fs::read_to_string(repo.join("views/CURRENT")).unwrap(),
        current
    );
}

#[test]
fn regular_policy_preserves_extensions_and_resolves_collisions() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("inputs");
    fs::create_dir_all(input.join("nested")).unwrap();
    fs::write(input.join("note.txt"), b"one").unwrap();
    fs::write(input.join("nested/note.txt"), b"two").unwrap();
    let rules = dir.path().join("rules.toml");
    fs::write(
        &rules,
        "[organization]\nfilename_policy = 'regular'\ndefault_filename = '{original_name}'\n",
    )
    .unwrap();
    let output = dir.path().join("out.zip");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "--zip".as_ref(),
        "--output".as_ref(),
        output.as_os_str(),
        "--rules".as_ref(),
        rules.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let zip = zip::ZipArchive::new(fs::File::open(&output).unwrap()).unwrap();
    let names: Vec<_> = (0..zip.len())
        .map(|i| zip.by_index_data(i).unwrap().name().unwrap().into_owned())
        .filter(|p| !["layout.jsonl", "export.json", "manifest.jsonl"].contains(&p.as_str()))
        .collect();
    assert_eq!(names.len(), 2);
    assert!(
        names
            .iter()
            .all(|n| n.ends_with(".txt") && !n.contains(".sample"))
    );
    assert!(names.iter().any(|n| n == "text/note.txt"));
    assert_ne!(names[0], names[1]);
}

#[test]
fn regular_policy_is_refused_for_archive_ingest_and_reorganize() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.zip");
    common::archive(&input, &[("note.txt", b"hello")]);
    let rules = dir.path().join("regular.toml");
    fs::write(
        &rules,
        "[organization]\nfilename_policy = 'regular'\ndefault_filename = '{original_name}'\n",
    )
    .unwrap();
    let blocked = dir.path().join("blocked");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--rules".as_ref(),
        rules.as_os_str(),
        "--output".as_ref(),
        blocked.as_os_str(),
    ]);
    assert!(!out.status.success());
    assert!(!blocked.exists());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("archive"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let repo = dir.path().join("repo");
    assert!(common::ingest(&input, &repo, "1").status.success());
    let current = fs::read_to_string(repo.join("views/CURRENT")).unwrap();
    let out = common::run(&[
        "reorganize".as_ref(),
        repo.as_os_str(),
        "--rules".as_ref(),
        rules.as_os_str(),
    ]);
    assert!(!out.status.success());
    assert_eq!(
        fs::read_to_string(repo.join("views/CURRENT")).unwrap(),
        current
    );
}

#[test]
fn zip_statistics_describe_published_bytes_and_total_time() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("note.txt");
    fs::write(&input, vec![b'a'; 65536]).unwrap();
    let output = dir.path().join("out.zip");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "--zip".as_ref(),
        "--output".as_ref(),
        output.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let size = fs::metadata(output).unwrap().len();
    assert_eq!(report["zip"]["output_bytes"], size);
    assert_eq!(report["zip"]["payload_bytes"], 65536);
    assert_eq!(report["zip"]["saved_bytes"], 65536 - size);
    let expected = (1.0 - size as f64 / 65536.0) * 100.0;
    assert!((report["zip"]["savings_percent"].as_f64().unwrap() - expected).abs() < 1e-8);
    assert!(
        report["elapsed_seconds"].as_f64().unwrap()
            >= report["zip"]["ingest_seconds"].as_f64().unwrap()
    );
}

#[test]
fn custom_staging_is_private_excluded_and_cleaned_up() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = dir.path().join("scratch");
    fs::create_dir(&scratch).unwrap();
    let input = dir.path().join("note.txt");
    fs::write(&input, b"hello").unwrap();
    let config = dir.path().join("config.toml");
    fs::write(
        &config,
        format!(
            "input_mode = 'files'\nzip = true\nstaging_dir = {:?}\n",
            scratch
        ),
    )
    .unwrap();
    let output = dir.path().join("out.zip");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--config".as_ref(),
        config.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read_dir(&scratch).unwrap().count(), 0);
    assert_eq!(
        fs::metadata(output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&scratch, &link).unwrap();
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--config".as_ref(),
        config.as_os_str(),
        "--staging-dir".as_ref(),
        link.as_os_str(),
        "--output".as_ref(),
        dir.path().join("blocked.zip").as_os_str(),
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("symlink"));
    assert!(!dir.path().join("blocked.zip").exists());
}

#[test]
fn empty_zip_payload_reports_signed_growth_without_a_percentage() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("empty.txt");
    fs::write(&input, b"").unwrap();
    let output = dir.path().join("out.zip");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "--zip".as_ref(),
        "--output".as_ref(),
        output.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["zip"]["payload_bytes"], 0);
    assert!(report["zip"]["savings_percent"].is_null());
    assert_eq!(
        report["zip"]["saved_bytes"].as_i64().unwrap(),
        -(fs::metadata(output).unwrap().len() as i64)
    );
}

#[test]
fn failed_and_cancelled_preview_leave_destination_and_staging_untouched() {
    use bfsort::{
        app::config::{Config, InputMode},
        ingest::pipeline,
    };
    use std::sync::atomic::AtomicBool;
    let dir = tempfile::tempdir().unwrap();
    let scratch = dir.path().join("scratch");
    fs::create_dir(&scratch).unwrap();
    let input = dir.path().join("file.txt");
    fs::write(&input, b"hello").unwrap();
    let output = dir.path().join("repo");
    let mut config = Config {
        inputs: vec![input],
        output: output.clone(),
        input_mode: InputMode::Files,
        staging_dir: Some(scratch.clone()),
        ..Config::default()
    };
    assert!(pipeline::preview(&config, &AtomicBool::new(true)).is_err());
    assert!(!output.exists());
    assert_eq!(fs::read_dir(&scratch).unwrap().count(), 0);
    config.limits.max_entry_bytes = Some(1);
    let error = pipeline::preview(&config, &AtomicBool::new(false))
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("file.txt") && error.contains("file size limit exceeded"),
        "{error}"
    );
    assert!(!output.exists());
    assert_eq!(fs::read_dir(&scratch).unwrap().count(), 0);
}

#[test]
fn zip_preview_validates_output_password_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("file.txt");
    fs::write(&input, b"hello").unwrap();
    let password = dir.path().join("password.txt");
    fs::write(&password, "secret\n").unwrap();
    fs::set_permissions(&password, fs::Permissions::from_mode(0o644)).unwrap();
    let output = dir.path().join("out.zip");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "--zip".as_ref(),
        "--dry-run".as_ref(),
        "--output".as_ref(),
        output.as_os_str(),
        "--output-password-file".as_ref(),
        password.as_os_str(),
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("permissions"));
    assert!(!output.exists());
}
