// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Password candidate handling, ZIP authentication, and refusal to publish corrupt payloads.

#![cfg(unix)]
use crate::common;
use std::{fs::File, io::Write, os::unix::fs::PermissionsExt};
use zip::{ZipWriter, unstable::write::FileOptionsExt, write::SimpleFileOptions};
#[test]
/// Ensure mixed encryption formats and per-entry passwords work safely.
fn mixed_encryption_and_different_passwords_work_without_leakage() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("mixed.zip");
    let mut zip = ZipWriter::new(File::create(&input).unwrap());
    let plain = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, options) in [
        ("plain", plain),
        (
            "aes",
            plain.with_aes_encryption(zip::AesMode::Aes256, "aes-fixture"),
        ),
        (
            "legacy",
            plain.with_deprecated_encryption(b"legacy-fixture").unwrap(),
        ),
    ] {
        zip.start_file(name, options).unwrap();
        zip.write_all(b"synthetic harmless data").unwrap();
    }
    zip.finish().unwrap();
    let inspection = common::run(&["inspect".as_ref(), input.as_os_str()]);
    assert!(inspection.status.success());
    let data: serde_json::Value = serde_json::from_slice(&inspection.stdout).unwrap();
    assert_eq!(data[0]["entries"][0]["encrypted"], false);
    assert_eq!(data[0]["entries"][1]["encrypted"], true);
    assert_eq!(data[0]["entries"][2]["encrypted"], true);
    let passwords = dir.path().join("passwords.txt");
    std::fs::write(&passwords, "wrong-fixture\naes-fixture\nlegacy-fixture\n").unwrap();
    std::fs::set_permissions(&passwords, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = dir.path().join("repo");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
        "--password-file".as_ref(),
        passwords.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(common::manifest(&output).len(), 3);
    for secret in ["wrong-fixture", "aes-fixture", "legacy-fixture"] {
        assert!(!String::from_utf8_lossy(&out.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&out.stderr).contains(secret));
    }
    let again = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
        "--password-file".as_ref(),
        passwords.as_os_str(),
    ]);
    assert!(again.status.success());
    let stats = common::run(&["stats".as_ref(), output.as_os_str()]);
    let stats: serde_json::Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(stats["occurrences"], 3);
}
#[test]
/// Ensure corrupted payloads never reach canonical storage.
fn corrupted_payload_is_not_committed() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("corrupt.zip");
    let mut zip = ZipWriter::new(File::create(&input).unwrap());
    zip.start_file(
        "safe",
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .unwrap();
    zip.write_all(b"abc").unwrap();
    zip.finish().unwrap();
    let mut bytes = std::fs::read(&input).unwrap();
    let pos = bytes.windows(3).position(|w| w == b"abc").unwrap();
    bytes[pos] ^= 1;
    std::fs::write(&input, bytes).unwrap();
    let output = dir.path().join("repo");
    let out = common::ingest(&input, &output, "1");
    assert_eq!(out.status.code(), Some(1));
    assert!(common::manifest(&output).is_empty());
    assert_eq!(
        std::fs::read_dir(output.join("objects")).unwrap().count(),
        0
    );
}
#[test]
/// Ensure tampered AES authentication data is rejected.
fn tampered_aes_authentication_tag_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("aes.zip");
    let mut zip = ZipWriter::new(File::create(&input).unwrap());
    zip.start_file(
        "safe",
        SimpleFileOptions::default().with_aes_encryption(zip::AesMode::Aes256, "fixture"),
    )
    .unwrap();
    zip.write_all(b"harmless").unwrap();
    zip.finish().unwrap();
    let mut archive = zip::ZipArchive::new(File::open(&input).unwrap()).unwrap();
    let entry = archive.by_index_raw(0).unwrap();
    let offset = entry.data_start().unwrap() + entry.compressed_size() - 1;
    drop(entry);
    drop(archive);
    let mut bytes = std::fs::read(&input).unwrap();
    bytes[offset as usize] ^= 1;
    std::fs::write(&input, bytes).unwrap();
    let passwords = dir.path().join("passwords");
    std::fs::write(&passwords, "fixture\n").unwrap();
    std::fs::set_permissions(&passwords, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = dir.path().join("repo");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
        "--password-file".as_ref(),
        passwords.as_os_str(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(common::manifest(&output).is_empty());
}

#[test]
fn unzip_only_uses_configured_passwords_and_seals_multiple_archives() {
    let temp = tempfile::tempdir().unwrap();
    let encrypted = temp.path().join("encrypted.zip");
    let plain = temp.path().join("plain.zip");
    let mut zip = ZipWriter::new(File::create(&encrypted).unwrap());
    zip.add_directory("empty/", SimpleFileOptions::default())
        .unwrap();
    zip.start_file(
        "payload.txt",
        SimpleFileOptions::default().with_aes_encryption(zip::AesMode::Aes256, "fixture"),
    )
    .unwrap();
    zip.write_all(b"encrypted fixture").unwrap();
    zip.finish().unwrap();
    common::archive(&plain, &[("payload.txt", b"plain fixture")]);

    let passwords = temp.path().join("passwords.txt");
    std::fs::write(&passwords, "fixture\n").unwrap();
    std::fs::set_permissions(&passwords, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = temp.path().join("ingest.toml");
    std::fs::write(
        &config,
        format!("password_file = {:?}\n", passwords.to_str().unwrap()),
    )
    .unwrap();
    let output = temp.path().join("extracted");
    let result = common::run(&[
        "ingest".as_ref(),
        "--unzip-only".as_ref(),
        "-c".as_ref(),
        config.as_os_str(),
        encrypted.as_os_str(),
        plain.as_os_str(),
        "-o".as_ref(),
        output.as_os_str(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(output.join("encrypted/empty").is_dir());
    for (relative, expected) in [
        ("encrypted/payload.txt", &b"encrypted fixture"[..]),
        ("plain/payload.txt", &b"plain fixture"[..]),
    ] {
        let file = output.join(relative);
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0
        );
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(std::fs::read(file).unwrap(), expected);
    }
}
