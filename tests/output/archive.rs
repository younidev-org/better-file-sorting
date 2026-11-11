//! ZIP inspection and archive discovery, including corrupt inputs and symlink exclusion.

use std::{fs::File, io::Write, process::Command};
use zip::{ZipWriter, write::SimpleFileOptions};
/// Build a harmless single-entry ZIP fixture.
fn archive(path: &std::path::Path) {
    let mut zip = ZipWriter::new(File::create(path).unwrap());
    zip.start_file("folder/hello.txt", SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"harmless").unwrap();
    zip.finish().unwrap();
}
#[test]
/// Ensure inspection identifies ZIP content without creating extracted files.
fn inspect_detects_content_without_extracting() {
    let dir = tempfile::tempdir().unwrap();
    archive(&dir.path().join("not-a-zip.bin"));
    let out = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .arg("--json")
        .arg("inspect")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let records: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(records[0]["entries"][0]["name"], "folder/hello.txt");
    assert_eq!(records[0]["entries"][0]["size"], 8);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
#[test]
/// Ensure malformed ZIP bytes return a failure.
fn malformed_zip_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.zip");
    std::fs::write(&path, b"PK\x03\x04garbage").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .arg("--json")
        .arg("inspect")
        .arg(path)
        .output()
        .unwrap();
    assert!(!out.status.success());
}
#[test]
/// Ensure nonrecursive discovery skips nested input directories.
fn nonrecursive_skips_nested_archives() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("nested")).unwrap();
    archive(&dir.path().join("nested/a.zip"));
    let out = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .arg("--json")
        .args(["inspect", "--recursive", "false"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap(),
        serde_json::json!([])
    );
}
#[cfg(unix)]
#[test]
/// Ensure discovery does not follow symlinked input trees.
fn discovery_skips_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    archive(&outside.path().join("a.zip"));
    std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .arg("--json")
        .arg("inspect")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap(),
        serde_json::json!([])
    );
}
