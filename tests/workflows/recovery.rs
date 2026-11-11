//! End-to-end retry and cleanup safety tests.
//!
//! Check that retry selects only recorded failed inputs and that nested ancestry
//! survives removal and reclamation.

use crate::common;
use std::{ffi::OsStr, fs};

#[test]
fn retry_failed_reprocesses_only_the_recorded_bad_archive() {
    let t = tempfile::tempdir().unwrap();
    let inputs = t.path().join("inputs");
    fs::create_dir(&inputs).unwrap();
    let good = inputs.join("good.zip");
    let bad = inputs.join("bad.zip");
    common::archive(&good, &[("good.txt", b"good")]);
    fs::write(&bad, b"PK\x03\x04broken").unwrap();
    let repo = t.path().join("repo");
    let result = common::run(&[
        "ingest".as_ref(),
        inputs.as_os_str(),
        "--extract".as_ref(),
        "-o".as_ref(),
        repo.as_os_str(),
        "--resume".as_ref(),
    ]);
    assert_eq!(
        result.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let operations = bfsort::operations::status(&repo).unwrap();
    let id = &operations[0].id;
    let outcomes = bfsort::repository::catalog::read(&repo)
        .unwrap()
        .inputs(id)
        .unwrap();
    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes.iter().filter(|r| r.state == "failed").count(), 1);
    common::archive(&bad, &[("fixed.txt", b"fixed")]);
    let result = common::run(&[
        "retry".as_ref(),
        repo.as_os_str(),
        "--operation".as_ref(),
        OsStr::new(id),
        "--failed".as_ref(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["accepted"], 1);
    assert_eq!(report["reused_occurrences"], 0);
    let rows = bfsort::repository::metadata::load(&repo).unwrap();
    assert_eq!(rows.len(), 2);
    let history = bfsort::operations::status(&repo).unwrap();
    let retry = history
        .iter()
        .find(|r| r.retry_of.as_ref() == Some(id))
        .unwrap();
    let retried = bfsort::repository::catalog::read(&repo)
        .unwrap()
        .inputs(&retry.id)
        .unwrap();
    assert_eq!(retried.len(), 1);
    assert!(retried[0].source_path.ends_with("bad.zip"));
}

#[test]
fn structural_ancestors_are_referenced_and_allow_leaf_removal() {
    let t = tempfile::tempdir().unwrap();
    let parent = t.path().join("parent.zip");
    common::archive(
        &parent,
        &[("keep.pdf", b"%PDF-1.7\n"), ("other.txt", b"other")],
    );
    let root = t.path().join("root.zip");
    common::archive(&root, &[("parent.zip", &fs::read(&parent).unwrap())]);
    let config = t.path().join("nested.toml");
    fs::write(&config,"input_mode='archives'\n[archive]\nnested_extraction=true\nmax_depth=2\n[filters]\ninclude_extensions=['pdf','txt']\n").unwrap();
    let repo = t.path().join("repo");
    let result = common::run(&[
        "ingest".as_ref(),
        root.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "-o".as_ref(),
        repo.as_os_str(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["summary"]["occurrences"], 2);
    assert_eq!(report["summary"]["orphan_objects"], 0);
    let result = common::run(&[
        "remove".as_ref(),
        repo.as_os_str(),
        "--include-ext".as_ref(),
        "pdf".as_ref(),
        "--dry-run".as_ref(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
