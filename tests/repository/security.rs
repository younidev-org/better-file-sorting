// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Filesystem security, hostile inputs, and staging recovery after forced termination.

#![cfg(unix)]
use crate::common;
use bfsort::{app::config::SecurityMode, repository::storage::Repository};
use std::os::unix::fs::PermissionsExt;
#[test]
/// Ensure output symlinks and weak password files fail closed.
fn output_symlink_and_insecure_password_file_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.zip");
    common::archive(&input, &[("safe", b"abc")]);
    let outside = tempfile::tempdir().unwrap();
    let output = dir.path().join("repo");
    std::os::unix::fs::symlink(outside.path(), &output).unwrap();
    assert!(!common::ingest(&input, &output, "1").status.success());
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    let passwords = dir.path().join("passwords");
    std::fs::write(&passwords, "harmless-fixture").unwrap();
    std::fs::set_permissions(&passwords, std::fs::Permissions::from_mode(0o644)).unwrap();
    let output = dir.path().join("clean");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
        "--password-file".as_ref(),
        passwords.as_os_str(),
    ]);
    assert!(!out.status.success());
    assert!(!output.exists());
}
#[test]
/// Ensure abandoned staging cleanup does not follow symlinks.
fn abandoned_staging_is_removed_without_following_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("repo");
    let repo = Repository::open(&root, SecurityMode::Sealed).unwrap();
    let abandoned = repo.staging().join("run-abandoned");
    std::fs::create_dir(&abandoned).unwrap();
    let outside = dir.path().join("keep");
    std::fs::write(&outside, b"harmless").unwrap();
    std::os::unix::fs::symlink(&outside, abandoned.join("link")).unwrap();
    drop(repo);
    let _repo = Repository::open(&root, SecurityMode::Sealed).unwrap();
    assert!(!abandoned.exists());
    assert_eq!(std::fs::read(outside).unwrap(), b"harmless");
}
#[test]
/// Ensure special filesystem entries and expansion bombs are rejected.
fn special_entries_and_expansion_bombs_are_rejected() {
    use std::{fs::File, io::Write};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("special.zip");
    let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
    zip.start_file(
        "link",
        zip::write::SimpleFileOptions::default().external_attributes(0o120777 << 16),
    )
    .unwrap();
    zip.write_all(b"target").unwrap();
    zip.finish().unwrap();
    let out = common::ingest(&path, &dir.path().join("special"), "1");
    assert_eq!(out.status.code(), Some(1));
    let path = dir.path().join("bomb.zip");
    common::archive(&path, &[("zeros", &vec![0; 2_000_000])]);
    let bounded = dir.path().join("bounded.toml");
    std::fs::write(&bounded, "[limits]\nmax_expansion_ratio=1000\n").unwrap();
    let output = dir.path().join("bomb");
    let out = common::run(&[
        "ingest".as_ref(),
        path.as_os_str(),
        "--extract".as_ref(),
        "-c".as_ref(),
        bounded.as_os_str(),
        "-o".as_ref(),
        output.as_os_str(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    let out = common::ingest(&path, &dir.path().join("unlimited"), "1");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
#[test]
/// Ensure forced stops leave protected staging and allow later recovery.
fn forced_stop_leaves_no_readable_payload_and_next_ingest_recovers() {
    use std::{
        fs::File,
        io::Write,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("many.zip");
    let mut zip = zip::ZipWriter::new(File::create(&input).unwrap());
    for index in 0..1000 {
        zip.start_file(
            format!("{index}.bin"),
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        zip.write_all(&[42; 65536]).unwrap();
    }
    zip.finish().unwrap();
    let output = dir.path().join("repo");
    let mut child = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .arg("--json")
        .args(["ingest", "--extract"])
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_staged = false;
    while Instant::now() < deadline {
        if let Ok(dirs) = std::fs::read_dir(output.join(".staging")) {
            saw_staged = dirs
                .flatten()
                .any(|d| std::fs::read_dir(d.path()).is_ok_and(|mut files| files.next().is_some()));
        }
        if saw_staged || child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if !saw_staged {
        let _ = child.kill();
        let _ = child.wait();
        panic!("did not observe staging before deadline");
    }
    child.kill().unwrap();
    child.wait().unwrap();
    for e in walkdir::WalkDir::new(output.join(".staging"))
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
    {
        assert_eq!(e.metadata().unwrap().permissions().mode() & 0o777, 0);
    }
    let recovered = common::ingest(&input, &output, "2");
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let stats: serde_json::Value = serde_json::from_slice(&recovered.stdout).unwrap();
    assert_eq!(stats["summary"]["occurrences"], 1000);
    assert_eq!(stats["summary"]["orphan_objects"], 0);
    assert_eq!(
        std::fs::read_dir(output.join(".staging")).unwrap().count(),
        0
    );
}
