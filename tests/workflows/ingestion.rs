// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! CLI ingestion and view publication, including sealed repositories and read-only previews.

#![cfg(unix)]
use crate::common;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[test]
/// Ensure reorganization is metadata-only and preserves old generations.
fn reorganize_uses_sealed_metadata_and_preserves_previous_view() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.zip");
    common::archive(
        &input,
        &[("a.pdf", b"%PDF-1.7\n"), ("b.pdf", b"%PDF-1.7\n")],
    );
    let output = dir.path().join("repo");
    let out = common::ingest(&input, &output, "2");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let before = std::fs::read_to_string(output.join("views/CURRENT")).unwrap();
    let rules = dir.path().join("rules.toml");
    std::fs::write(&rules, "[organization]\nduplicates = 'all'\ndefault_directory = 'custom/{file_type}'\ndefault_filename = '{original_name}.sample'").unwrap();
    let dry = common::run(&[
        "reorganize".as_ref(),
        output.as_os_str(),
        "--rules".as_ref(),
        rules.as_os_str(),
        "--dry-run".as_ref(),
    ]);
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Vec<serde_json::Value>>(&dry.stdout)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        std::fs::read_to_string(output.join("views/CURRENT")).unwrap(),
        before
    );
    let out = common::run(&[
        "reorganize".as_ref(),
        output.as_os_str(),
        "--rules".as_ref(),
        rules.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let current = std::fs::read_to_string(output.join("views/CURRENT")).unwrap();
    assert_ne!(before, current);
    assert!(output.join("views").join(before.trim()).is_dir());
    let view = output
        .join("views")
        .join(current.trim())
        .join("custom/pdf/a.pdf.sample");
    let rows = common::manifest(&output);
    let hash = rows[0]["sha256"].as_str().unwrap();
    let object = output.join("objects").join(&hash[..2]).join(hash);
    assert_eq!(
        view.metadata().unwrap().ino(),
        object.metadata().unwrap().ino()
    );
    assert_eq!(view.metadata().unwrap().permissions().mode() & 0o777, 0);
    std::fs::write(&rules, "[organization]\ndefault_directory = '../escape'").unwrap();
    let failed = common::run(&[
        "reorganize".as_ref(),
        output.as_os_str(),
        "--rules".as_ref(),
        rules.as_os_str(),
    ]);
    assert!(!failed.status.success());
    assert_eq!(
        std::fs::read_to_string(output.join("views/CURRENT")).unwrap(),
        current
    );
}
#[test]
/// Ensure invalid rules and ingest dry runs do not create repositories.
fn ingest_invalid_rules_and_dry_run_do_not_create_repository() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.zip");
    common::archive(&input, &[("a", b"abc")]);
    let output = dir.path().join("repo");
    let rules = dir.path().join("rules.toml");
    std::fs::write(&rules, "[organization]\ndefault_filename = '{bad}.sample'").unwrap();
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
        "--rules".as_ref(),
        rules.as_os_str(),
    ]);
    assert!(!out.status.success());
    assert!(!output.exists());
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
        "--dry-run".as_ref(),
    ]);
    assert!(out.status.success());
    assert!(!output.exists());
}
#[test]
/// Ensure published view directories retain owner-only permissions.
fn published_view_directories_are_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.zip");
    common::archive(&input, &[("a", b"abc")]);
    let output = dir.path().join("repo");
    assert!(common::ingest(&input, &output, "1").status.success());
    let current = std::fs::read_to_string(output.join("views/CURRENT")).unwrap();
    assert_eq!(
        output
            .join("views")
            .join(current.trim())
            .metadata()
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}
#[test]
/// Ensure manifest-only views never create payload hard links.
fn manifest_only_view_has_no_payload_links() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.zip");
    common::archive(&input, &[("a", b"abc")]);
    let output = dir.path().join("repo");
    let rules = dir.path().join("rules.toml");
    std::fs::write(&rules, "[organization]\nview_mode = 'manifest'").unwrap();
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
        "--rules".as_ref(),
        rules.as_os_str(),
    ]);
    assert!(out.status.success());
    let current = std::fs::read_to_string(output.join("views/CURRENT")).unwrap();
    let view = output.join("views").join(current.trim());
    assert_eq!(std::fs::read_dir(&view).unwrap().count(), 1);
    assert!(view.join("rules.json").is_file());
    assert!(!view.join("layout.jsonl").exists());
    assert_eq!(
        bfsort::repository::catalog::read(&output)
            .unwrap()
            .view_plan(current.trim())
            .unwrap()
            .len(),
        1
    );
    let rows = common::manifest(&output);
    let hash = rows[0]["sha256"].as_str().unwrap();
    assert_eq!(
        output
            .join("objects")
            .join(&hash[..2])
            .join(hash)
            .metadata()
            .unwrap()
            .nlink(),
        1
    );
}
