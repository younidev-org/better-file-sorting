//! SQLite catalog constraints and transaction tests.
//!
//! Exercise private catalog access, indexed selection, ancestry, tombstones,
//! retained views, and operation records. Corruption and conflict cases must fail
//! without partially committing a batch.

#![cfg(unix)]
use bfsort::{
    app::config::SecurityMode,
    repository::{
        catalog::{self, Catalog},
        metadata::{self, Occurrence},
        storage::Repository,
    },
    selection::Filters,
};
use std::{fs, os::unix::fs::PermissionsExt};
fn row(index: usize) -> Occurrence {
    serde_json::from_value(serde_json::json!({"occurrence_id":metadata::digest(index.to_string().as_bytes()),"sha256":metadata::digest(b"abc"),"size":3,"file_type":"text","original_name":"a.TXT","original_entry_name":"a.TXT","original_stem":"a","original_extension":".TXT","source_archive":"source","source_path":format!("source{index}"),"entry_index":index,"encrypted":false,"ingest_date":"today","run_id":"run"})).unwrap()
}
fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("repo");
    let repo = Repository::open(&root, SecurityMode::Sealed).unwrap();
    repo.with_catalog(|catalog| catalog.insert(&row(0)))
        .unwrap();
    (t, root)
}
fn rows(c: &Catalog) -> Vec<Occurrence> {
    c.select(&Filters::default(), false).unwrap()
}
#[test]
fn new_repositories_have_private_catalogs() {
    let (_t, root) = fixture();
    assert_eq!(rows(&catalog::read(&root).unwrap()).len(), 1);
    assert!(catalog::exists(&root).unwrap());
    assert_eq!(
        fs::metadata(root.join(catalog::FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(rows(&catalog::read(&root).unwrap()).len(), 1);
}
#[test]
fn transaction_conflict_rolls_back_and_sql_selection_matches_predicate() {
    let (_t, root) = fixture();
    let mut c = catalog::write(&root).unwrap();
    let mut conflict = row(0);
    conflict.size = 8;
    assert!(c.insert_many(&[row(1), conflict]).is_err());
    assert_eq!(rows(&c).len(), 1);
    c.insert(&row(1)).unwrap();
    let f = Filters {
        include_extensions: vec!["txt".into()],
        min_size: Some(3),
        max_size: Some(3),
        ..Default::default()
    };
    assert_eq!(c.counts(&f).unwrap().occurrences, 2);
    assert_eq!(c.counts(&f).unwrap().unique_objects, 1);
    assert!(c.select(&f, false).unwrap().iter().all(|r| f.matches(r)));
    c.remove(&[row(0).occurrence_id].into()).unwrap();
    assert_eq!(rows(&c).len(), 1);
    assert_eq!(c.select(&f, true).unwrap().len(), 2);
    c.integrity().unwrap();
}
#[test]
fn versions_and_permissions_fail_closed() {
    let (_t, root) = fixture();
    drop(catalog::write(&root).unwrap());
    let p = root.join(catalog::FILE_NAME);
    let connection = rusqlite::Connection::open(&p).unwrap();
    connection.pragma_update(None, "user_version", 999).unwrap();
    drop(connection);
    assert!(catalog::read(&root).is_err());
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(catalog::write(&root).is_err());
}

#[test]
fn unsafe_sidecar_blocks_catalog_access() {
    let (_t, root) = fixture();
    let database = root.join(catalog::FILE_NAME);
    let sidecar = root.join(format!("{}-journal", catalog::FILE_NAME));
    std::os::unix::fs::symlink(&database, &sidecar).unwrap();
    assert!(catalog::read(&root).is_err());
    assert!(catalog::write(&root).is_err());
    assert!(database.is_file());
}

#[test]
fn deferred_ancestry_and_tombstone_guard_are_atomic() {
    let (_t, root) = fixture();
    let mut catalog = catalog::write(&root).unwrap();
    let parent = row(1);
    let mut child = row(2);
    child.nested = Some(metadata::NestedProvenance {
        schema_version: 1,
        parent_sha256: parent.sha256.clone(),
        parent_occurrence_id: Some(parent.occurrence_id.clone()),
        root_source: "source".into(),
        root_input_hash: parent.sha256.clone(),
        archive_depth: 0,
        entry_chain: vec![0],
    });
    catalog
        .insert_many(&[child.clone(), parent.clone()])
        .unwrap();
    catalog.integrity().unwrap();
    assert!(
        catalog
            .remove(&[parent.occurrence_id.clone()].into())
            .is_err()
    );
    assert!(catalog.removed().unwrap().is_empty());
    catalog
        .remove(&[parent.occurrence_id, child.occurrence_id].into())
        .unwrap();
    assert_eq!(catalog.removed().unwrap().len(), 2);
}
#[test]
fn index_record_corruption_and_numeric_overflow_fail_closed() {
    let (_t, root) = fixture();
    let mut catalog = catalog::write(&root).unwrap();
    let mut huge = row(1);
    huge.size = u64::MAX;
    assert!(catalog.insert(&huge).is_err());
    assert_eq!(rows(&catalog).len(), 1);
    drop(catalog);
    let connection = rusqlite::Connection::open(root.join(catalog::FILE_NAME)).unwrap();
    connection
        .execute("UPDATE occurrences SET normalized_extension='exe'", [])
        .unwrap();
    drop(connection);
    let catalog = catalog::read(&root).unwrap();
    assert!(rows_result(&catalog).is_err());
    assert!(catalog.integrity().is_err());
}
fn rows_result(c: &Catalog) -> anyhow::Result<Vec<Occurrence>> {
    c.select(&Filters::default(), true)
}
#[test]
fn catalog_read_is_read_only() {
    let (_t, root) = fixture();
    drop(catalog::write(&root).unwrap());
    let mut catalog = catalog::read(&root).unwrap();
    assert_eq!(rows(&catalog).len(), 1);
    assert!(catalog.insert(&row(1)).is_err());
    assert_eq!(rows(&catalog).len(), 1);
}

#[test]
fn all_filter_columns_match_shared_predicate_and_classification_rollback() {
    use bfsort::detection::{classifier::Format, mismatch::Status};
    let (_t, root) = fixture();
    let mut catalog = catalog::write(&root).unwrap();
    let mut second = row(1);
    second.original_extension = "pdf".into();
    second.detection.detected_format = Format::Pdf;
    second.mismatch.status = Status::Mismatch;
    catalog.insert(&second).unwrap();
    let filters = [
        Filters {
            include_formats: vec![Format::Pdf],
            ..Default::default()
        },
        Filters {
            exclude_formats: vec![Format::Pdf],
            ..Default::default()
        },
        Filters {
            mismatch: Some(Status::Mismatch),
            ..Default::default()
        },
        Filters {
            exclude_extensions: vec![".TXT".into()],
            ..Default::default()
        },
        Filters {
            min_size: Some(u64::MAX),
            ..Default::default()
        },
        Filters {
            max_size: Some(u64::MAX),
            sha256: Some(second.sha256.clone()),
            ..Default::default()
        },
    ];
    let all = rows(&catalog);
    for filter in filters {
        let expected: Vec<_> = all
            .iter()
            .filter(|r| filter.matches(r))
            .map(|r| r.occurrence_id.clone())
            .collect();
        let actual: Vec<_> = catalog
            .select(&filter, false)
            .unwrap()
            .into_iter()
            .map(|r| r.occurrence_id)
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(
            catalog.counts(&filter).unwrap().occurrences,
            expected.len() as u64
        );
    }
    let mut changed = row(0);
    changed.detection.detected_format = Format::Elf;
    assert!(
        catalog
            .update_classifications(&[changed.clone(), row(99)])
            .is_err()
    );
    assert_eq!(
        rows(&catalog)[0].detection.detected_format,
        Format::NotEvaluated
    );
    catalog.update_classifications(&[changed]).unwrap();
    assert_eq!(
        catalog
            .counts(&Filters {
                include_formats: vec![Format::Elf],
                ..Default::default()
            })
            .unwrap()
            .occurrences,
        1
    );
}
#[test]
fn same_identity_replay_preserves_provenance_and_views_pin_removed_hashes() {
    use bfsort::organization::rules::Planned;
    let (_t, root) = fixture();
    let mut catalog = catalog::write(&root).unwrap();
    let original = row(0);
    let mut replay = original.clone();
    replay.source_path = "changed provenance".into();
    catalog.insert(&replay).unwrap();
    assert_eq!(rows(&catalog)[0].source_path, original.source_path);
    catalog
        .record_view(
            "view-test",
            &[Planned {
                path: "text/a.sample".into(),
                sha256: original.sha256.clone(),
                occurrence_id: original.occurrence_id.clone(),
            }],
        )
        .unwrap();
    catalog.remove(&[original.occurrence_id].into()).unwrap();
    assert_eq!(
        catalog.referenced_hashes().unwrap(),
        [original.sha256].into()
    );
    catalog.integrity().unwrap();
}

#[test]
fn interrupted_and_cancelled_operations_round_trip() {
    let (_t, root) = fixture();
    let mut catalog = catalog::write(&root).unwrap();
    for state in ["interrupted", "cancelled"] {
        let record = bfsort::operations::Record {
            schema_version: 1,
            app_version: env!("CARGO_PKG_VERSION").into(),
            retry_of: None,
            counts: None,
            checkpoints: Vec::new(),
            last_error: None,
            id: format!("op-{state}"),
            command: "ingest".into(),
            args: vec!["ingest".into(), "input".into()],
            cwd: root.clone(),
            settings_files: Default::default(),
            state: state.into(),
            started_at: "2026-11-05T00:00:00Z".into(),
            finished_at: Some("2026-11-05T00:01:00Z".into()),
            exit_code: Some(130),
        };
        catalog
            .put_operation(&record.id, &serde_json::to_string(&record).unwrap())
            .unwrap();
    }
    let records = catalog.operations().unwrap();
    assert_eq!(records.len(), 2);
    for text in records {
        let record: bfsort::operations::Record = serde_json::from_str(&text).unwrap();
        catalog.put_operation(&record.id, &text).unwrap();
    }
    catalog.integrity().unwrap();
}
