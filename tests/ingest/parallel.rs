//! Parallel ingestion, content deduplication, and preservation of source provenance.

#![cfg(unix)]
use crate::common;
#[test]
/// Ensure worker counts produce deterministic provenance and deduplication.
fn parallel_ingest_preserves_provenance_and_deduplicates() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    std::fs::create_dir(&input).unwrap();
    common::archive(&input.join("a.zip"), &[("a.txt", b"abc"), ("empty", b"")]);
    common::archive(&input.join("b.zip"), &[("b.txt", b"abc")]);
    let mut expected = None;
    for workers in ["1", "4"] {
        let output = dir.path().join(format!("repo-{workers}"));
        let out = common::ingest(&input, &output, workers);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let rows = common::manifest(&output);
        assert_eq!(rows.len(), 3);
        let mut ids: Vec<_> = rows
            .iter()
            .map(|r| r["occurrence_id"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        if let Some(ref expected) = expected {
            assert_eq!(&ids, expected);
        } else {
            expected = Some(ids);
        }
        let stats = common::run(&["stats".as_ref(), output.as_os_str()]);
        assert!(stats.status.success());
        let stats: serde_json::Value = serde_json::from_slice(&stats.stdout).unwrap();
        assert_eq!(stats["occurrences"], 3);
        assert_eq!(stats["unique_samples"], 2);
        assert_eq!(stats["duplicate_occurrences"], 1);
    }
}
#[test]
/// Ensure one corrupt archive does not discard valid neighboring samples.
fn corrupt_archive_does_not_discard_good_samples() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    std::fs::create_dir(&input).unwrap();
    common::archive(&input.join("good.zip"), &[("good", b"abc")]);
    std::fs::write(input.join("bad.zip"), b"PK\x03\x04bad").unwrap();
    let output = dir.path().join("repo");
    let result = common::ingest(&input, &output, "2");
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(common::manifest(&output).len(), 1);
}
#[test]
/// Ensure archive limits report unprocessed entries as failures.
fn archive_limit_does_not_silently_skip_remaining_entries() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.zip");
    common::archive(&input, &[("a", b"a"), ("b", b"b")]);
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        "[limits]\nmax_entry_bytes = 1\nmax_archive_bytes = 1",
    )
    .unwrap();
    let output = dir.path().join("repo");
    let out = common::run(&[
        "ingest".as_ref(),
        "--extract".as_ref(),
        input.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
        "--config".as_ref(),
        config.as_os_str(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["failures"], 1);
}
#[test]
/// Ensure invalid UTF-8 source paths retain distinct identities.
fn non_utf8_archive_paths_keep_distinct_provenance() {
    use std::os::unix::ffi::OsStringExt;
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    std::fs::create_dir(&input).unwrap();
    for byte in [0xfe, 0xff] {
        let name = std::ffi::OsString::from_vec(vec![byte, b'.', b'z', b'i', b'p']);
        common::archive(&input.join(name), &[("same", b"abc")]);
    }
    let output = dir.path().join("repo");
    let out = common::ingest(&input, &output, "2");
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["summary"]["occurrences"], 2);
}
#[test]
/// Ensure full archive entry paths remain available as metadata.
fn full_original_entry_name_is_preserved_as_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.zip");
    common::archive(&input, &[("nested/deeper/file.txt", b"abc")]);
    let output = dir.path().join("repo");
    assert!(common::ingest(&input, &output, "1").status.success());
    let rows = common::manifest(&output);
    assert_eq!(rows[0]["original_entry_name"], "nested/deeper/file.txt");
    assert_eq!(rows[0]["original_name"], "file.txt");
}
