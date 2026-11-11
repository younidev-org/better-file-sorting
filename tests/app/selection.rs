//! Shared selector behavior across ingestion and repository commands.
//!
//! Exercise CLI and configuration precedence, occurrence counts, retry, and
//! removal. Check that filtered operations retain references outside the selection.

use crate::common::run;
use std::fs;

#[test]
fn content_filters_select_members_and_queries_distinguish_occurrences() {
    let t = tempfile::tempdir().unwrap();
    let zip = t.path().join("input.zip");
    crate::common::archive(
        &zip,
        &[
            ("a.pdf", b"%PDF-1.7\n"),
            ("renamed.pdf", b"hello"),
            ("b.txt", b"hello"),
        ],
    );
    let repo = t.path().join("repo");
    let out = run(&[
        "ingest".as_ref(),
        zip.as_os_str(),
        "-o".as_ref(),
        repo.as_os_str(),
        "--include-format".as_ref(),
        "pdf".as_ref(),
        "--resume".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(crate::common::manifest(&repo).len(), 1);
    let out = run(&["query".as_ref(), repo.as_os_str(), "--count".as_ref()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["occurrences"], 1);
    assert_eq!(value["unique_objects"], 1);
    // Changing selection must not reuse the old one-member checkpoint.
    let out = run(&[
        "ingest".as_ref(),
        zip.as_os_str(),
        "-o".as_ref(),
        repo.as_os_str(),
        "--resume".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run(&[
        "query".as_ref(),
        repo.as_os_str(),
        "--include-ext".as_ref(),
        "PDF".as_ref(),
        "--count".as_ref(),
    ]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["occurrences"], 2);
}

#[test]
fn filter_config_validation_and_cli_override() {
    let t = tempfile::tempdir().unwrap();
    let config = t.path().join("bfs.toml");
    fs::write(
        &config,
        "[filters]\ninclude_extensions = ['txt']\nexclude_extensions = ['exe']\n",
    )
    .unwrap();
    let out = run(&[
        "config".as_ref(),
        "validate".as_ref(),
        "-c".as_ref(),
        config.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::write(&config, "[filters]\ninclude_formats = ['not_a_format']\n").unwrap();
    let out = run(&[
        "config".as_ref(),
        "validate".as_ref(),
        "-c".as_ref(),
        config.as_os_str(),
    ]);
    assert!(!out.status.success());
}

#[test]
fn history_tracks_cli_ingest_and_removed_entries_do_not_resurrect() {
    let t = tempfile::tempdir().unwrap();
    let file = t.path().join("note.txt");
    let repo = t.path().join("repo");
    fs::write(&file, b"hello").unwrap();
    let ingest = || {
        run(&[
            "ingest".as_ref(),
            file.as_os_str(),
            "--input-mode".as_ref(),
            "files".as_ref(),
            "-o".as_ref(),
            repo.as_os_str(),
            "--resume".as_ref(),
        ])
    };
    assert!(ingest().status.success());
    let out = run(&["status".as_ref(), repo.as_os_str()]);
    assert!(out.status.success());
    let history: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(history[0]["state"], "completed");
    let out = run(&[
        "remove".as_ref(),
        repo.as_os_str(),
        "--include-ext".as_ref(),
        "txt".as_ref(),
        "--confirm".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(ingest().status.success());
    let out = run(&[
        "ingest".as_ref(),
        file.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "-o".as_ref(),
        repo.as_os_str(),
        "--dry-run".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(preview["summary"]["occurrences"], 0);
    let out = run(&["query".as_ref(), repo.as_os_str(), "--count".as_ref()]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["occurrences"], 0);
    let out = run(&["verify".as_ref(), repo.as_os_str()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run(&["prune".as_ref(), repo.as_os_str(), "--dry-run".as_ref()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["candidate_objects"], 0); // Retained view pins the shared object.
}

#[test]
fn reclassification_skips_reclaimed_removed_payloads() {
    use bfsort::{
        app::config::SecurityMode,
        repository::{cleanup, metadata, storage::Repository},
    };
    let t = tempfile::tempdir().unwrap();
    let file = t.path().join("note.txt");
    let root = t.path().join("repo");
    fs::write(&file, b"hello").unwrap();
    let out = run(&[
        "ingest".as_ref(),
        file.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "-o".as_ref(),
        root.as_os_str(),
        "--security-mode".as_ref(),
        "standard".as_ref(),
    ]);
    assert!(out.status.success());
    let rows = metadata::load(&root).unwrap();
    let filters = bfsort::selection::Filters {
        include_extensions: vec!["txt".into()],
        ..Default::default()
    };
    cleanup::remove(&root, &filters, false, true).unwrap();
    // Drop all retained views in this disposable fixture to model reclaimable data.
    fs::remove_dir_all(root.join("views")).unwrap();
    bfsort::repository::security::private_dir(&root.join("views")).unwrap();
    // Explicitly expire the corresponding catalog references in this fixture too.
    let connection =
        rusqlite::Connection::open(root.join(bfsort::repository::catalog::FILE_NAME)).unwrap();
    connection.execute("DELETE FROM view_entries", []).unwrap();
    drop(connection);
    cleanup::prune(&root, false, true).unwrap();
    let repo = Repository::existing(&root).unwrap();
    assert_eq!(repo.mode(), SecurityMode::Standard);
    assert!(!repo.object(&rows[0].sha256).unwrap().exists());
    assert!(metadata::reclassify(&repo, &std::sync::atomic::AtomicBool::new(false), false).is_ok());
}

#[test]
fn selected_stats_do_not_call_other_referenced_objects_orphans() {
    let t = tempfile::tempdir().unwrap();
    let zip = t.path().join("input.zip");
    crate::common::archive(&zip, &[("a.pdf", b"%PDF-1.7\n"), ("b.txt", b"hello")]);
    let repo = t.path().join("repo");
    assert!(
        run(&[
            "ingest".as_ref(),
            zip.as_os_str(),
            "-o".as_ref(),
            repo.as_os_str()
        ])
        .status
        .success()
    );
    let out = run(&[
        "stats".as_ref(),
        repo.as_os_str(),
        "--include-ext".as_ref(),
        "pdf".as_ref(),
    ]);
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["occurrences"], 1);
    assert_eq!(value["stored_objects"], 2);
    assert_eq!(value["orphan_objects"], 0);
}

#[test]
fn repository_commands_compose_and_retry_with_machine_output() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    let repo = t.path().join("repo");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("a.txt"), b"hello").unwrap();
    fs::write(source.join("b.pdf"), b"%PDF-1.7\n").unwrap();
    let out = run(&[
        "ingest".as_ref(),
        source.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "-o".as_ref(),
        repo.as_os_str(),
        "--security-mode".as_ref(),
        "standard".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let status = run(&["status".as_ref(), repo.as_os_str()]);
    let history: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    let id = history[0]["id"].as_str().unwrap();
    let out = run(&[
        "retry".as_ref(),
        repo.as_os_str(),
        "--operation".as_ref(),
        id.as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap();
    let out = run(&[
        "retry".as_ref(),
        repo.as_os_str(),
        "--operation".as_ref(),
        id.as_ref(),
        "--quiet".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty());
    let sampled = t.path().join("sampled");
    let out = run(&[
        "sample".as_ref(),
        repo.as_os_str(),
        "--count".as_ref(),
        "1".as_ref(),
        "--seed".as_ref(),
        "42".as_ref(),
        "-o".as_ref(),
        sampled.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for args in [
        vec!["verify".as_ref(), sampled.as_os_str(), "--full".as_ref()],
        vec!["diff".as_ref(), repo.as_os_str(), sampled.as_os_str()],
    ] {
        let out = run(&args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap();
    }
    let merged = t.path().join("merged");
    let out = run(&[
        "merge".as_ref(),
        repo.as_os_str(),
        sampled.as_os_str(),
        "-o".as_ref(),
        merged.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let split = t.path().join("parts");
    let out = run(&[
        "split".as_ref(),
        merged.as_os_str(),
        "--by".as_ref(),
        "extension".as_ref(),
        "-o".as_ref(),
        split.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(split.join("ext-747874/security.json").exists());
    assert!(split.join("ext-706466/security.json").exists());
}

#[test]
fn removing_nested_leaf_does_not_require_original_outer_archive_object() {
    let t = tempfile::tempdir().unwrap();
    let zip = t.path().join("input.zip");
    crate::common::archive(&zip, &[("a.txt", b"hello"), ("b.pdf", b"%PDF-1.7\n")]);
    let config = t.path().join("nested.toml");
    fs::write(
        &config,
        "input_mode = 'archives'\n[archive]\nnested_extraction = true\nmax_depth = 1\n",
    )
    .unwrap();
    let repo = t.path().join("repo");
    let out = run(&[
        "ingest".as_ref(),
        zip.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "-o".as_ref(),
        repo.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run(&[
        "remove".as_ref(),
        repo.as_os_str(),
        "--include-ext".as_ref(),
        "txt".as_ref(),
        "--confirm".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows = bfsort::repository::metadata::load(&repo).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].original_extension, "pdf");
    let out = run(&[
        "analyze".as_ref(),
        repo.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "--dry-run".as_ref(),
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("logical removal"));
}
