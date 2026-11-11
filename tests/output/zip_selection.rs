// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! ZIP directory selection, output layout, and atomic publication under path conflicts.

#![cfg(unix)]
use crate::common;
use std::{fs, os::unix::fs::PermissionsExt};

fn fixture(root: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let input = root.join("input");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("a.pdf"), b"%PDF-1.7\n").unwrap();
    fs::write(input.join("b.txt"), b"hello\n").unwrap();
    fs::write(input.join("c.bin"), b"\0\x01\x02").unwrap();
    let rules = root.join("rules.toml");
    fs::write(&rules, "[organization]\nfilename_policy = 'regular'\ndefault_directory = 'other'\ndefault_filename = '{original_name}'\n[[rules]]\nname = 'pdf'\n[rules.match]\noriginal_extension = 'pdf'\n[rules.output]\ndirectory = 'documents/pdf'\nfilename = '{original_name}'\n[[rules]]\nname = 'txt'\n[rules.match]\noriginal_extension = 'txt'\n[rules.output]\ndirectory = 'documents/text'\nfilename = '{original_name}'\n").unwrap();
    (input, rules)
}

#[test]
fn selected_directories_share_one_zip_without_duplicate_entries() {
    let dir = tempfile::tempdir().unwrap();
    let (input, rules) = fixture(dir.path());
    let output = dir.path().join("chosen.zip");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "--rules".as_ref(),
        rules.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
        "--zip-dir".as_ref(),
        "documents".as_ref(),
        "--zip-dir".as_ref(),
        "documents/pdf".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut zip = zip::ZipArchive::new(fs::File::open(&output).unwrap()).unwrap();
    assert_eq!(zip.len(), 3);
    assert!(zip.by_name("documents/pdf/a.pdf").is_ok());
    assert!(zip.by_name("documents/text/b.txt").is_ok());
    assert!(zip.by_name("other/c.bin").is_err());
    assert!(zip.by_name("layout.jsonl").is_err());
    let report: serde_json::Value =
        serde_json::from_reader(zip.by_name("export.json").unwrap()).unwrap();
    assert_eq!(report["payload_entries"], 2);
}

#[test]
fn separate_zips_use_top_level_or_selected_nested_directories() {
    for selected in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (input, rules) = fixture(dir.path());
        let output = dir.path().join("exports");
        let password = dir.path().join("password.txt");
        fs::write(&password, "secret\n").unwrap();
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
        let mut args = vec![
            "ingest".as_ref(),
            input.as_os_str(),
            "--input-mode".as_ref(),
            "files".as_ref(),
            "--rules".as_ref(),
            rules.as_os_str(),
            "--output".as_ref(),
            output.as_os_str(),
            "--zip-each-dir".as_ref(),
            "--output-password-file".as_ref(),
            password.as_os_str(),
        ];
        if selected {
            args.extend_from_slice(&[
                "--zip-dir".as_ref(),
                "documents/pdf".as_ref(),
                "--zip-dir".as_ref(),
                "other".as_ref(),
            ]);
        }
        let out = common::run(&args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let name = if selected {
            "documents/pdf.zip"
        } else {
            "documents.zip"
        };
        let mut zip = zip::ZipArchive::new(fs::File::open(output.join(name)).unwrap()).unwrap();
        assert_eq!(zip.len(), if selected { 2 } else { 3 });
        assert!(
            zip.by_name_decrypt("documents/pdf/a.pdf", b"secret")
                .is_ok()
        );
        assert!(output.join("other.zip").is_file());
        assert!(!output.join("repository").exists());
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["zip"]["archives"].as_array().unwrap().len(), 2);
        assert!(!common::run(&args).status.success());
    }
}

#[test]
fn preview_and_config_apply_directory_selection() {
    let dir = tempfile::tempdir().unwrap();
    let (input, rules) = fixture(dir.path());
    let config = dir.path().join("config.toml");
    fs::write(
        &config,
        "input_mode = 'files'\nzip_dirs = ['documents/pdf']\nzip_each_dir = true\n",
    )
    .unwrap();
    let output = dir.path().join("exports");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--config".as_ref(),
        config.as_os_str(),
        "--rules".as_ref(),
        rules.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
        "--dry-run".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(preview["plan"].as_array().unwrap().len(), 1);
    assert_eq!(
        preview["archives"][0]["output"],
        output.join("documents/pdf.zip").to_str().unwrap()
    );
    assert!(!output.exists());
}

#[test]
fn invalid_or_missing_directories_never_publish_output() {
    let dir = tempfile::tempdir().unwrap();
    let (input, rules) = fixture(dir.path());
    let output = dir.path().join("exports");
    for name in [
        "../escape",
        "/absolute",
        "documents//pdf",
        "documents/./pdf",
        "documents\\pdf",
        "missing",
        "document",
    ] {
        let out = common::run(&[
            "ingest".as_ref(),
            input.as_os_str(),
            "--input-mode".as_ref(),
            "files".as_ref(),
            "--rules".as_ref(),
            rules.as_os_str(),
            "--output".as_ref(),
            output.as_os_str(),
            "--zip-dir".as_ref(),
            name.as_ref(),
            "--zip-each-dir".as_ref(),
        ]);
        assert!(!out.status.success(), "accepted {name}");
        assert!(!output.exists());
    }
}

#[test]
fn directory_publication_never_replaces_a_concurrently_created_empty_destination() {
    let dir = tempfile::tempdir().unwrap();
    let staged = dir.path().join("staged");
    let output = dir.path().join("output");
    fs::create_dir(&staged).unwrap();
    fs::write(staged.join("ready.zip"), b"complete").unwrap();
    assert!(!output.exists());
    fs::create_dir(&output).unwrap(); // Another writer won after preflight.
    assert!(bfsort::repository::security::publish_directory(&staged, &output).is_err());
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
    assert_eq!(fs::read(staged.join("ready.zip")).unwrap(), b"complete");
}

#[test]
fn conflicting_archive_file_and_directory_paths_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let config = bfsort::app::config::Config {
        zip_each_dir: true,
        zip_dirs: vec!["a".into(), "a.zip/nested".into()],
        output: root.path().join("output"),
        ..Default::default()
    };
    let entries: Vec<_> = ["a/file.sample", "a.zip/nested/file.sample"]
        .into_iter()
        .map(|path| bfsort::organization::rules::Planned {
            path: path.into(),
            sha256: "a".repeat(64),
            occurrence_id: "b".repeat(64),
        })
        .collect();
    assert!(
        bfsort::output::archive::plan_exports(
            &entries,
            &config,
            &bfsort::organization::rules::Rules::default()
        )
        .is_err()
    );
    assert!(!config.output.exists());
}
