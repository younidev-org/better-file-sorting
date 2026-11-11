//! Logical removal and physical reclamation tests.
//!
//! Check confirmation and dry-run behavior, object references held by retained views
//! and recovery records, and conservative refusal of unsupported metadata.

#![cfg(unix)]
use bfsort::{
    app::config::SecurityMode,
    repository::{cleanup, metadata, storage::Repository},
    selection::Filters,
};
use std::io::Write;
#[test]
fn orphan_prune_requires_confirmation_and_preserves_dry_run() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    let repo = Repository::open(&root, SecurityMode::Sealed).unwrap();
    let hash = metadata::digest(b"abc");
    let path = repo.object(&hash).unwrap();
    let mut file = tempfile::NamedTempFile::new_in(repo.staging()).unwrap();
    file.write_all(b"abc").unwrap();
    repo.commit(file, &hash, 3).unwrap();
    drop(repo);
    assert!(cleanup::prune(&root, false, false).is_err());
    assert_eq!(
        cleanup::prune(&root, true, false)
            .unwrap()
            .candidate_objects,
        1
    );
    assert!(path.exists());
    assert_eq!(
        cleanup::prune(&root, false, true)
            .unwrap()
            .candidate_objects,
        1
    );
    assert!(!path.exists());
}
#[test]
fn removal_requires_selector_and_confirmation() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    drop(Repository::open(&root, SecurityMode::Standard).unwrap());
    assert!(cleanup::remove(&root, &Filters::default(), true, false).is_err());
    let filters = Filters {
        include_extensions: vec!["txt".into()],
        ..Default::default()
    };
    assert!(cleanup::remove(&root, &filters, false, false).is_err());
    assert_eq!(
        cleanup::remove(&root, &filters, true, false)
            .unwrap()
            .selected_occurrences,
        0
    );
    assert!(cleanup::removed(&root).unwrap().is_empty());
}

#[test]
fn retained_catalog_view_and_duplicate_occurrences_pin_objects() {
    use bfsort::organization::{organizer, rules::Rules};
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    let repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    let hash = metadata::digest(b"abc");
    let path = repo.object(&hash).unwrap();
    let mut file = tempfile::NamedTempFile::new_in(repo.staging()).unwrap();
    file.write_all(b"abc").unwrap();
    repo.commit(file, &hash, 3).unwrap();
    for (index, extension) in ["txt", "pdf"].iter().enumerate() {
        let row:metadata::Occurrence=serde_json::from_value(serde_json::json!({"occurrence_id":metadata::digest(index.to_string().as_bytes()),"sha256":hash,"size":3,"file_type":"text","original_name":format!("a.{extension}"),"original_entry_name":format!("a.{extension}"),"original_stem":"a","original_extension":extension,"source_archive":"source","source_path":"source","entry_index":index,"encrypted":false,"ingest_date":"today","run_id":"run"})).unwrap();
        metadata::store(&repo, &row).unwrap();
    }
    let rules = Rules::parse("version=1\n[organization]\nview_mode='manifest'").unwrap();
    let rows = metadata::load(&root).unwrap();
    organizer::organize(&repo, &rules, &rules.plan(&rows).unwrap()).unwrap();
    drop(repo);
    let filters = Filters {
        include_extensions: vec!["txt".into()],
        ..Default::default()
    };
    assert_eq!(
        cleanup::remove(&root, &filters, false, true)
            .unwrap()
            .selected_occurrences,
        1
    );
    assert_eq!(metadata::load(&root).unwrap().len(), 1);
    assert_eq!(
        cleanup::prune(&root, true, false)
            .unwrap()
            .candidate_objects,
        0
    );
    let filters = Filters {
        include_extensions: vec!["pdf".into()],
        ..Default::default()
    };
    cleanup::remove(&root, &filters, false, true).unwrap();
    assert!(metadata::load(&root).unwrap().is_empty());
    assert_eq!(
        cleanup::prune(&root, false, true)
            .unwrap()
            .candidate_objects,
        0
    );
    assert!(path.exists());
    assert!(
        bfsort::repository::verify::run(&root, false, &std::sync::atomic::AtomicBool::new(false))
            .unwrap()
            .failures
            .is_empty()
    );
    std::fs::write(&path, b"xyz").unwrap();
    assert!(
        !bfsort::repository::verify::run(&root, true, &std::sync::atomic::AtomicBool::new(false))
            .unwrap()
            .failures
            .is_empty()
    );
}

#[test]
fn unknown_receipt_blocks_prune_and_interrupted_journal_retries() {
    use bfsort::repository::security;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    let repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    let hash = metadata::digest(b"abc");
    let object = repo.object(&hash).unwrap();
    let mut file = tempfile::NamedTempFile::new_in(repo.staging()).unwrap();
    file.write_all(b"abc").unwrap();
    repo.commit(file, &hash, 3).unwrap();
    drop(repo);
    security::private_dir(&root.join("operations")).unwrap();
    security::private_dir(&root.join("operations/extraction")).unwrap();
    let receipt = root.join("operations/extraction/unknown.json");
    std::fs::write(&receipt, b"{\"schema_version\":99}").unwrap();
    security::seal(
        &std::fs::File::open(&receipt).unwrap(),
        SecurityMode::Standard,
    )
    .unwrap();
    assert!(cleanup::prune(&root, false, true).is_err());
    assert!(object.exists());
    std::fs::remove_file(receipt).unwrap();
    let journal = root.join("operations/prune.json");
    std::fs::write(
        &journal,
        serde_json::to_vec(&serde_json::json!({"schema_version":1,"hashes":[hash]})).unwrap(),
    )
    .unwrap();
    security::seal(
        &std::fs::File::open(&journal).unwrap(),
        SecurityMode::Standard,
    )
    .unwrap();
    assert_eq!(
        cleanup::prune(&root, false, true)
            .unwrap()
            .candidate_objects,
        1
    );
    assert!(!object.exists());
    assert!(!journal.exists());
}

#[test]
fn corrupt_known_receipt_stops_prune_and_full_verification() {
    use bfsort::repository::security;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    drop(Repository::open(&root, SecurityMode::Standard).unwrap());
    security::private_dir(&root.join("operations")).unwrap();
    security::private_dir(&root.join("operations/extraction")).unwrap();
    let receipt = root.join("operations/extraction/known.json");
    std::fs::write(&receipt,serde_json::to_vec(&serde_json::json!({"schema_version":1,"checksum":"0".repeat(64),"archive_hash":"a".repeat(64),"policy":"policy","entries":0,"bytes":0,"children":[]})).unwrap()).unwrap();
    security::seal(
        &std::fs::File::open(&receipt).unwrap(),
        SecurityMode::Standard,
    )
    .unwrap();
    assert!(cleanup::prune(&root, false, true).is_err());
    let report =
        bfsort::repository::verify::run(&root, true, &std::sync::atomic::AtomicBool::new(false))
            .unwrap();
    assert!(report.failures.iter().any(|e| e.contains("checksum")));
}

#[test]
fn obsolete_view_metadata_blocks_reclamation() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    let repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    let hash = metadata::digest(b"abc");
    let object = repo.object(&hash).unwrap();
    let mut file = tempfile::NamedTempFile::new_in(repo.staging()).unwrap();
    file.write_all(b"abc").unwrap();
    repo.commit(file, &hash, 3).unwrap();
    drop(repo);
    let view = root.join("views/view-obsolete");
    bfsort::repository::security::private_dir(&view).unwrap();
    std::fs::write(
        view.join("layout.jsonl"),
        format!("{{\"sha256\":\"{hash}\"}}\n"),
    )
    .unwrap();

    assert!(cleanup::prune(&root, false, true).is_err());
    assert!(object.is_file());
}
