//! SQLite persistence for input outcomes and retained view plans.
//!
//! Obsolete schemas are refused without changing the original catalog.

use bfsort::{
    app::config::SecurityMode,
    operations::InputOutcome,
    repository::{catalog, storage::Repository},
};

#[test]
fn input_results_and_view_plans_are_durable_sqlite_state() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("repo");
    let repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    let args = vec!["ingest".to_owned(), "input.zip".to_owned()];
    let mut guard = bfsort::operations::Guard::start(repo.root(), "ingest", &args).unwrap();
    let id = guard.id().to_owned();
    repo.with_catalog(|c| {
        c.record_input(
            &id,
            &InputOutcome {
                source_path: "/synthetic/input.zip".into(),
                state: "failed".into(),
                error: Some("synthetic failure".into()),
            },
        )
    })
    .unwrap();
    guard.finish(1).unwrap();
    let c = catalog::read(&root).unwrap();
    let rows = c.inputs(&id).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, "failed");
    assert!(c.view_plan("view-empty").unwrap().is_empty());
}

#[test]
fn older_catalog_is_refused_without_changes() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("repo");
    drop(Repository::open(&root, SecurityMode::Standard).unwrap());
    let file = tempfile::NamedTempFile::new_in(&root).unwrap();
    let c = rusqlite::Connection::open(file.path()).unwrap();
    c.execute_batch("CREATE TABLE objects(hash TEXT PRIMARY KEY,size INTEGER NOT NULL);
CREATE TABLE occurrences(id TEXT PRIMARY KEY,hash TEXT NOT NULL,normalized_extension TEXT NOT NULL,detected_format TEXT NOT NULL,mismatch TEXT NOT NULL,source_path TEXT NOT NULL,entry_index INTEGER NOT NULL,record TEXT NOT NULL);
CREATE TABLE ancestry(occurrence_id TEXT PRIMARY KEY,parent_id TEXT,parent_hash TEXT NOT NULL);
CREATE TABLE tombstones(id TEXT PRIMARY KEY);
CREATE TABLE view_entries(generation TEXT NOT NULL,path TEXT NOT NULL,occurrence_id TEXT NOT NULL,hash TEXT NOT NULL,PRIMARY KEY(generation,path));
CREATE TABLE operations(id TEXT PRIMARY KEY,record TEXT NOT NULL);
PRAGMA application_id=1111905073; PRAGMA user_version=1;").unwrap();
    drop(c);
    file.persist(root.join(catalog::FILE_NAME)).unwrap();
    let before = std::fs::read(root.join(catalog::FILE_NAME)).unwrap();
    assert!(catalog::read(&root).is_err());
    assert!(catalog::write(&root).is_err());
    assert_eq!(
        before,
        std::fs::read(root.join(catalog::FILE_NAME)).unwrap()
    );
}
