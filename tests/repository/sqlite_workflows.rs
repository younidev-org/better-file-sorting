//! End-to-end checks of SQLite catalog authority and interchange.
#![cfg(unix)]
use bfsort::{
    app::config::SecurityMode,
    repository::{
        metadata::{self, Occurrence},
        storage::Repository,
    },
};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .args(args)
        .output()
        .unwrap()
}
fn success(args: &[&str]) -> serde_json::Value {
    let result = cli(args);
    assert!(
        result.status.success(),
        "{args:?}: {} {}",
        String::from_utf8_lossy(&result.stderr),
        String::from_utf8_lossy(&result.stdout)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}
fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn ingest(directory: &Path) -> PathBuf {
    let inputs = directory.join("inputs");
    fs::create_dir(&inputs).unwrap();
    fs::write(
        inputs.join("message.txt"),
        b"catalog payload sentinel text\n",
    )
    .unwrap();
    let mut elf = vec![0u8; 64];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf[16] = 2;
    elf[18] = 62;
    elf[20] = 1;
    elf[52] = 64;
    fs::write(inputs.join("program.pdf"), elf).unwrap();
    let root = directory.join("repo");
    success(&[
        "ingest",
        text(&inputs),
        "--recursive",
        "true",
        "--security-mode",
        "standard",
        "-o",
        text(&root),
        "--json",
    ]);
    root
}
fn count(root: &Path, filters: &[&str]) -> usize {
    let mut args = vec!["query", text(root), "--count", "--json"];
    args.extend_from_slice(filters);
    success(&args)["occurrences"].as_u64().unwrap() as usize
}
fn private_write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn synthetic(index: usize) -> Occurrence {
    serde_json::from_value(serde_json::json!({
        "occurrence_id": metadata::digest(index.to_string().as_bytes()), "sha256": metadata::digest(b"abc"),
        "size":3,"file_type":"text","original_name":"a.txt","original_entry_name":"a.txt",
        "original_stem":"a","original_extension":"txt","source_archive":"","source_path":"legacy",
        "entry_index":index,"encrypted":false,"ingest_date":"2026-11-05","run_id":"legacy"
    })).unwrap()
}
fn fixture(root: &Path, rows: &[Occurrence]) {
    let repo = Repository::open(root, SecurityMode::Standard).unwrap();
    let mut file = tempfile::NamedTempFile::new_in(repo.staging()).unwrap();
    file.write_all(b"abc").unwrap();
    repo.commit(file, &metadata::digest(b"abc"), 3).unwrap();
    metadata::store_many(&repo, rows).unwrap();
}

fn snapshot(root: &Path, rows: &[Occurrence]) -> PathBuf {
    let repo = Repository::open(root, SecurityMode::Standard).unwrap();
    repo.with_catalog(|catalog| catalog.insert_many(rows))
        .unwrap();
    root.join("metadata.sqlite3")
}

#[test]
fn ingest_catalog_is_private_metadata_and_ignores_stale_jsonl() {
    let tmp = tempfile::tempdir().unwrap();
    let root = ingest(tmp.path());
    let database = root.join("metadata.sqlite3");
    assert!(database.exists());
    assert_eq!(
        fs::metadata(&database).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let connection = rusqlite::Connection::open(&database).unwrap();
    let blobs: i64 = connection
        .query_row(
            "SELECT count(*) FROM pragma_table_info('objects') WHERE upper(type) = 'BLOB'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(blobs, 0, "payloads must remain in object files");
    drop(connection);
    let rows = metadata::load(&root).unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert!(
            root.join("objects")
                .join(&row.sha256[..2])
                .join(row.sha256)
                .is_file()
        );
    }
    assert!(!root.join("manifests").exists());
    fs::create_dir(root.join("manifests")).unwrap();
    private_write(
        &root.join("manifests/stale.jsonl"),
        b"malformed stale export\n",
    );
    assert_eq!(count(&root, &[]), 2);
    assert_eq!(
        count(&root, &["--include-ext", "pdf", "--include-format", "elf"]),
        1
    );
    assert_eq!(
        count(&root, &["--include-ext", "pdf", "--include-format", "pdf"]),
        0
    );
    assert_eq!(
        count(
            &root,
            &["--include-ext", "pdf,txt", "--exclude-format", "elf"]
        ),
        1
    );
    assert_eq!(count(&root, &["--include-ext", "txt'"]), 0);
    assert_eq!(count(&root, &["--mismatch", "mismatch"]), 1);
    assert_eq!(
        count(
            &root,
            &[
                "--min-size",
                "60",
                "--max-size",
                "80",
                "--include-format",
                "elf"
            ]
        ),
        1
    );
    assert_eq!(count(&root, &["--min-size", "999999"]), 0);
    assert_eq!(count(&root, &["--max-size", "1"]), 0);
    success(&["verify", text(&root), "--full", "--json"]);
    success(&["prune", text(&root), "--dry-run", "--json"]);
}

#[test]
fn metadata_import_reads_a_sqlite_catalog_without_copying_payloads() {
    let tmp = tempfile::tempdir().unwrap();
    let root = ingest(tmp.path());
    let exported = root.join("metadata.sqlite3");
    assert!(
        tree_files(&root)
            .keys()
            .all(|p| p.extension().is_none_or(|e| e != "jsonl"))
    );
    let destination = tmp.path().join("imported");
    {
        let repo = Repository::open(&destination, SecurityMode::Standard).unwrap();
        for row in metadata::load(&root).unwrap() {
            let bytes = fs::read(
                root.join("objects")
                    .join(&row.sha256[..2])
                    .join(&row.sha256),
            )
            .unwrap();
            let mut file = tempfile::NamedTempFile::new_in(repo.staging()).unwrap();
            file.write_all(&bytes).unwrap();
            repo.commit(file, &row.sha256, row.size).unwrap();
        }
    }
    success(&[
        "metadata",
        "import",
        text(&destination),
        text(&exported),
        "--json",
    ]);
    assert_eq!(count(&destination, &[]), 2);
    assert_eq!(count(&destination, &["--include-format", "elf"]), 1);
    assert_eq!(
        serde_json::to_value(metadata::load(&root).unwrap()).unwrap(),
        serde_json::to_value(metadata::load(&destination).unwrap()).unwrap()
    );
}

#[test]
fn missing_catalog_fails_closed_even_with_a_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("legacy");
    fixture(&root, &[synthetic(0)]);
    fs::create_dir(root.join("manifests")).unwrap();
    private_write(
        &root.join("manifests/legacy.jsonl"),
        format!("{}\n", serde_json::to_string(&synthetic(0)).unwrap()).as_bytes(),
    );
    fs::remove_file(root.join("metadata.sqlite3")).unwrap();
    let before = tree_files(&root);
    assert!(
        !cli(&["query", text(&root), "--count", "--json"])
            .status
            .success()
    );
    assert!(
        !cli(&["metadata", "migrate", text(&root), "--json"])
            .status
            .success()
    );
    assert_eq!(tree_files(&root), before);
}

#[test]
fn unsupported_schema_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = ingest(tmp.path());
    let connection = rusqlite::Connection::open(root.join("metadata.sqlite3")).unwrap();
    connection.pragma_update(None, "user_version", 999).unwrap();
    drop(connection);
    assert!(
        !cli(&["query", text(&root), "--count", "--json"])
            .status
            .success()
    );
}

#[test]
fn corrupt_sqlite_import_does_not_publish_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    fixture(&root, &[synthetic(0)]);
    let invalid = snapshot(&tmp.path().join("invalid"), &[synthetic(1), synthetic(2)]);
    let connection = rusqlite::Connection::open(&invalid).unwrap();
    connection
        .execute(
            "UPDATE occurrences SET evidence='not-json' WHERE entry_index=2",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(
        !cli(&["metadata", "import", text(&root), text(&invalid), "--json"])
            .status
            .success()
    );
    assert_eq!(count(&root, &[]), 1);
}

#[test]
fn tombstones_reclassification_and_interchange_agree() {
    let tmp = tempfile::tempdir().unwrap();
    let root = ingest(tmp.path());
    success(&[
        "remove",
        text(&root),
        "--include-ext",
        "pdf",
        "--confirm",
        "--json",
    ]);
    assert_eq!(count(&root, &[]), 1);
    success(&["reclassify", text(&root), "--json"]);
    assert_eq!(count(&root, &["--include-ext", "pdf"]), 0);
    assert!(
        tree_files(&root)
            .keys()
            .all(|p| p.extension().is_none_or(|e| e != "jsonl"))
    );
    let stats = success(&["stats", text(&root), "--json"]);
    assert_eq!(stats["occurrences"], 1);
    success(&["verify", text(&root), "--full", "--json"]);
    success(&["prune", text(&root), "--dry-run", "--json"]);
}

#[test]
fn import_rejects_missing_objects_and_conflicting_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    fixture(&root, &[synthetic(0)]);
    let mut conflict = synthetic(0);
    conflict.source_path = "conflicting provenance".to_owned();
    let input = snapshot(&tmp.path().join("conflict"), &[conflict]);
    assert!(
        !cli(&["metadata", "import", text(&root), text(&input), "--json"])
            .status
            .success()
    );
    assert_eq!(metadata::load(&root).unwrap()[0].source_path, "legacy");

    let mut missing = synthetic(2);
    missing.sha256 = metadata::digest(b"absent bytes");
    let input = snapshot(&tmp.path().join("missing"), &[synthetic(1), missing]);
    assert!(
        !cli(&["metadata", "import", text(&root), text(&input), "--json"])
            .status
            .success()
    );
    assert_eq!(count(&root, &[]), 1);
}

#[test]
fn version_three_catalog_has_columns_and_refuses_older_versions() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    fixture(&root, &[synthetic(0)]);
    let path = root.join("metadata.sqlite3");
    let connection = rusqlite::Connection::open(&path).unwrap();
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 3);
    let has_record: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('occurrences') WHERE name='record')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!has_record);
    connection.pragma_update(None, "user_version", 2).unwrap();
    drop(connection);

    let before = fs::read(&path).unwrap();
    let result = cli(&["query", text(&root), "--count", "--json"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("re-ingest"));
    assert!(Repository::open(&root, SecurityMode::Standard).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn import_does_not_resurrect_removed_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    fixture(&root, &[]);
    let input = snapshot(&tmp.path().join("source"), &[synthetic(0), synthetic(1)]);
    let source = Repository::existing(input.parent().unwrap()).unwrap();
    source
        .with_catalog(|catalog| catalog.remove(&[synthetic(1).occurrence_id].into()))
        .unwrap();
    drop(source);
    let report = success(&["metadata", "import", text(&root), text(&input), "--json"]);
    assert_eq!(report["occurrences"], 1);
    assert_eq!(
        metadata::load(&root).unwrap()[0].occurrence_id,
        synthetic(0).occurrence_id
    );
}

fn tree_files(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    walkdir::WalkDir::new(root)
        .into_iter()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| {
            (
                entry.path().strip_prefix(root).unwrap().to_path_buf(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

#[test]
fn batched_metadata_rejects_missing_objects_without_partial_publication() {
    let t = tempfile::tempdir().unwrap();
    let root = ingest(t.path());
    let repo = Repository::existing(&root).unwrap();
    let rows = metadata::load(&root).unwrap();
    let mut first = rows[0].clone();
    first.occurrence_id = metadata::digest(b"new batch first");
    let mut missing = rows[1].clone();
    missing.occurrence_id = metadata::digest(b"new batch missing");
    missing.sha256 = metadata::digest(b"missing payload");
    assert!(metadata::store_many(&repo, &[first.clone(), missing]).is_err());
    assert!(
        !metadata::load(&root)
            .unwrap()
            .iter()
            .any(|r| r.occurrence_id == first.occurrence_id)
    );
    metadata::store_many(&repo, &[first]).unwrap();
    assert_eq!(metadata::load(&root).unwrap().len(), rows.len() + 1);
}

#[test]
fn export_zero_compression_stores_payloads_and_rejects_invalid_levels() {
    let t = tempfile::tempdir().unwrap();
    let root = ingest(t.path());
    let output = t.path().join("stored.zip");
    success(&[
        "export",
        text(&root),
        "--compression-level",
        "0",
        "-o",
        text(&output),
        "--json",
    ]);
    let mut archive = zip::ZipArchive::new(fs::File::open(output).unwrap()).unwrap();
    for i in 0..archive.len() {
        assert_eq!(
            archive.by_index(i).unwrap().compression(),
            zip::CompressionMethod::Stored
        );
    }
    assert!(
        !cli(&[
            "export",
            text(&root),
            "--compression-level",
            "10",
            "-o",
            text(&t.path().join("invalid.zip"))
        ])
        .status
        .success()
    );
}

#[test]
fn ingest_flushes_multiple_batches_and_tail_before_resume_checkpoint() {
    let t = tempfile::tempdir().unwrap();
    let archive = t.path().join("inputs.zip");
    let names: Vec<_> = (0..257).map(|i| format!("entry-{i}.txt")).collect();
    let entries: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), b"batch fixture".as_slice()))
        .collect();
    crate::common::archive(&archive, &entries);
    let root = t.path().join("repo");
    let args = [
        "ingest",
        text(&archive),
        "--extract",
        "--security-mode",
        "standard",
        "--resume",
        "-o",
        text(&root),
        "--json",
    ];
    success(&args);
    assert_eq!(metadata::load(&root).unwrap().len(), 257);
    success(&args);
    assert_eq!(metadata::load(&root).unwrap().len(), 257);
}
