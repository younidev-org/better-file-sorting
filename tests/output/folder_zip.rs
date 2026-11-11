// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Folder and archive ZIP export, optional encryption, and no-clobber publication.

#![cfg(unix)]
use crate::common;
use std::{fs, io::Read, os::unix::fs::PermissionsExt};

#[test]
fn folder_sort_uses_rules_and_preserves_sources() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("note.txt"), b"hello world\n").unwrap();
    let rules = dir.path().join("rules.toml");
    fs::write(&rules, "[organization]\ndefault_directory = 'sorted/{original_extension}'\ndefault_filename = '{original_name}.sample'\n").unwrap();
    let output = input.join("repository");
    for _ in 0..2 {
        let out = common::run(&[
            "ingest".as_ref(),
            input.as_os_str(),
            "--input-mode".as_ref(),
            "files".as_ref(),
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
    }
    assert_eq!(common::manifest(&output).len(), 1);
    let current = fs::read_to_string(output.join("views/CURRENT")).unwrap();
    assert!(
        output
            .join("views")
            .join(current.trim())
            .join("sorted/txt/note.txt.sample")
            .exists()
    );
    assert_eq!(fs::read(input.join("note.txt")).unwrap(), b"hello world\n");
}

#[test]
fn zip_only_roundtrip_with_optional_password_and_no_overwrite() {
    for encrypted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        fs::create_dir(&input).unwrap();
        let content = vec![b'a'; 65536];
        fs::write(input.join("note.txt"), &content).unwrap();
        let password = input.join("password.txt");
        fs::write(&password, "secret\n").unwrap();
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
        let output = input.join("sorted.zip");
        let mut args = vec![
            "ingest".as_ref(),
            input.as_os_str(),
            "--input-mode".as_ref(),
            "files".as_ref(),
            "--zip".as_ref(),
            "--output".as_ref(),
            output.as_os_str(),
        ];
        if encrypted {
            args.extend(["--output-password-file".as_ref(), password.as_os_str()]);
        } else {
            fs::remove_file(&password).unwrap();
        }
        let out = common::run(&args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let original_zip = fs::read(&output).unwrap();
        assert!(original_zip.len() < content.len());
        let mut zip = zip::ZipArchive::new(fs::File::open(&output).unwrap()).unwrap();
        assert_eq!(zip.len(), 2); // one payload and export report
        assert!(zip.by_name("layout.jsonl").is_err());
        assert!(zip.by_name("manifest.jsonl").is_err());
        let index = (0..zip.len())
            .find(|i| {
                zip.by_index_data(*i)
                    .unwrap()
                    .name()
                    .unwrap()
                    .ends_with(".sample")
            })
            .unwrap();
        assert_eq!(zip.by_index_data(index).unwrap().encrypted(), encrypted);
        if encrypted {
            assert!(zip.by_index_decrypt(index, b"wrong").is_err());
        }
        let mut entry = if encrypted {
            zip.by_index_decrypt(index, b"secret").unwrap()
        } else {
            zip.by_index(index).unwrap()
        };
        let mut bytes = vec![];
        entry.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, content);
        assert!(!common::run(&args).status.success());
        assert_eq!(fs::read(&output).unwrap(), original_zip);
        assert_eq!(
            fs::read_dir(&input).unwrap().count(),
            if encrypted { 3 } else { 2 }
        );
        assert_eq!(fs::read(input.join("note.txt")).unwrap(), content);
    }
}

#[test]
fn zip_does_not_publish_on_limit_failure_or_dry_run() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("note.txt");
    fs::write(&input, b"too large").unwrap();
    let output = dir.path().join("sorted.zip");
    let config = dir.path().join("config.toml");
    fs::write(
        &config,
        "input_mode = 'files'\nzip = true\n[limits]\nmax_entry_bytes = 2\n",
    )
    .unwrap();
    let args = [
        "ingest".as_ref(),
        input.as_os_str(),
        "--config".as_ref(),
        config.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
    ];
    assert!(!common::run(&args).status.success());
    assert!(!output.exists());
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "--zip".as_ref(),
        "--output".as_ref(),
        output.as_os_str(),
        "--dry-run".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!output.exists());
}

#[test]
fn file_mode_respects_recursion_symlinks_and_count_limit() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    fs::create_dir_all(input.join("nested")).unwrap();
    fs::write(input.join("top.txt"), b"top").unwrap();
    fs::write(input.join("nested/deep.txt"), b"deep").unwrap();
    std::os::unix::fs::symlink(input.join("top.txt"), input.join("link.txt")).unwrap();
    let output = dir.path().join("repository");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "--recursive".as_ref(),
        "false".as_ref(),
        "--output".as_ref(),
        output.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(common::manifest(&output).len(), 1);
    let config = dir.path().join("config.toml");
    fs::write(&config, "input_mode = 'files'\n[limits]\nmax_entries = 1\n").unwrap();
    let blocked = dir.path().join("blocked");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--config".as_ref(),
        config.as_os_str(),
        "--output".as_ref(),
        blocked.as_os_str(),
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("file count limit"));
    assert!(!blocked.exists());
}

#[test]
fn archive_inputs_can_publish_zip_with_manifest_policy() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.zip");
    common::archive(&input, &[("note.txt", b"hello")]);
    let output = dir.path().join("sorted.zip");
    let rules = dir.path().join("rules.toml");
    fs::write(&rules, "[organization]\nview_mode = 'manifest'\ndefault_directory = 'custom'\ndefault_filename = '{original_name}.sample'\n").unwrap();
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
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
    let mut zip = zip::ZipArchive::new(fs::File::open(&output).unwrap()).unwrap();
    let mut content = String::new();
    zip.by_name("custom/note.txt.sample")
        .unwrap()
        .read_to_string(&mut content)
        .unwrap();
    assert_eq!(content, "hello");
}

#[test]
fn rejects_invalid_output_password_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("note.txt");
    fs::write(&input, b"hello").unwrap();
    let password = dir.path().join("password.txt");
    fs::write(&password, "one\ntwo\n").unwrap();
    fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
    let output = dir.path().join("sorted.zip");
    for zip in [false, true] {
        let mut args = vec![
            "ingest".as_ref(),
            input.as_os_str(),
            "--input-mode".as_ref(),
            "files".as_ref(),
            "--output".as_ref(),
            output.as_os_str(),
            "--output-password-file".as_ref(),
            password.as_os_str(),
        ];
        if zip {
            args.push("--zip".as_ref());
        }
        let out = common::run(&args);
        assert!(!out.status.success());
        let error = String::from_utf8_lossy(&out.stderr);
        assert!(
            error.contains(if zip { "exactly one" } else { "requires ZIP" }),
            "{error}"
        );
        assert!(!output.exists());
    }
}

#[test]
fn password_hardlinks_are_excluded_from_output() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("note.txt"), b"hello").unwrap();
    let password = dir.path().join("password.txt");
    fs::write(&password, "secret\n").unwrap();
    fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&password, input.join("innocent.txt")).unwrap();
    let output = dir.path().join("sorted.zip");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "--zip".as_ref(),
        "--output".as_ref(),
        output.as_os_str(),
        "--password-file".as_ref(),
        password.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let zip = zip::ZipArchive::new(fs::File::open(&output).unwrap()).unwrap();
    assert_eq!(zip.len(), 2, "unexpected extra ZIP entries");
    assert_eq!(
        zip.file_names()
            .filter(|name| name.as_ref().is_ok_and(|name| name.ends_with(".sample")))
            .count(),
        1,
        "password hardlink leaked into ZIP"
    );
}
