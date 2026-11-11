// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Canonical object publication, permissions, deduplication, and orphan accounting.

#![cfg(unix)]
use bfsort::{
    app::config::SecurityMode, detection::classifier::classify, repository::storage::Repository,
};
use std::{
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
};
#[test]
/// Ensure format classification uses content signatures rather than names.
fn classification_uses_content() {
    for (bytes, expected) in [
        (b"\x7fELFhello".as_slice(), "elf"),
        (b"%PDF-1.7\n", "pdf"),
        (b"hello\n", "text"),
        (b"", "unknown"),
        (b"\0\x01\x02\xff", "unknown"),
    ] {
        assert_eq!(classify(bytes), expected);
    }
}
#[test]
/// Ensure sealed canonical commits are atomic and deduplicated.
fn canonical_commit_is_sealed_atomic_and_deduplicated() {
    let dir = tempfile::tempdir().unwrap();
    let repo = Repository::open(&dir.path().join("repo"), SecurityMode::Sealed).unwrap();
    let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    for _ in 0..2 {
        let mut file = tempfile::NamedTempFile::new_in(repo.staging()).unwrap();
        file.write_all(b"abc").unwrap();
        repo.commit(file, hash, 3).unwrap();
    }
    let path = repo.object(hash).unwrap();
    assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0);
    assert_eq!(std::fs::read_dir(repo.staging()).unwrap().count(), 0);
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        1
    );
    if std::fs::metadata("/proc/self")
        .map(|m| m.uid() != 0)
        .unwrap_or(true)
    {
        assert!(std::fs::read(&path).is_err());
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::process::Command::new(&path).status().is_err());
    }
    assert!(Repository::open(repo.root(), SecurityMode::Standard).is_err());
}
#[test]
/// Ensure standard objects are private and symlink paths are refused.
fn standard_objects_are_private_and_symlinks_refused() {
    let dir = tempfile::tempdir().unwrap();
    let repo = Repository::open(&dir.path().join("repo"), SecurityMode::Standard).unwrap();
    let hash = "a".repeat(64);
    let mut file = tempfile::NamedTempFile::new_in(repo.staging()).unwrap();
    file.write_all(b"abc").unwrap();
    repo.commit(file, &hash, 3).unwrap();
    assert_eq!(
        repo.object(&hash)
            .unwrap()
            .metadata()
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(repo.object("../../bad").is_err());
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(repo.root(), &link).unwrap();
    assert!(Repository::open(&link, SecurityMode::Sealed).is_err());
}
#[test]
/// Ensure Java bytecode is not misclassified as Mach-O.
fn java_class_is_not_macho() {
    assert_eq!(classify(b"\xca\xfe\xba\xbe\x00\x00\x00\x3d"), "other");
}
#[test]
/// Ensure reports account for orphaned canonical objects.
fn statistics_include_objects_left_before_manifest_commit() {
    let dir = tempfile::tempdir().unwrap();
    let repo = Repository::open(&dir.path().join("repo"), SecurityMode::Sealed).unwrap();
    let mut file = tempfile::NamedTempFile::new_in(repo.staging()).unwrap();
    file.write_all(b"abc").unwrap();
    repo.commit(file, &"a".repeat(64), 3).unwrap();
    let summary = bfsort::output::report::summary(&repo, &[]).unwrap();
    assert_eq!(summary.stored_bytes, 3);
}
