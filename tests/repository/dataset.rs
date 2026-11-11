//! Dataset sampling, splitting, and resume tests.
//!
//! Check seeded allocation, structural ancestry closure, verified reuse of copied
//! objects, and rejection of changed source snapshots.

#![cfg(unix)]
use bfsort::{
    app::config::SecurityMode,
    repository::{
        derive::{self, Kind, Options, SampleOptions, SamplingUnit, Stratum},
        metadata::{self, Occurrence},
        storage::Repository,
    },
    selection::Filters,
};
use std::{io::Write, sync::atomic::AtomicBool};
fn fixture(root: &std::path::Path) {
    let repo = Repository::open(root, SecurityMode::Standard).unwrap();
    for index in 0..10 {
        let bytes = format!("payload {}", index / 2);
        let hash = metadata::digest(bytes.as_bytes());
        let mut file = tempfile::NamedTempFile::new_in(repo.staging()).unwrap();
        file.write_all(bytes.as_bytes()).unwrap();
        repo.commit(file, &hash, bytes.len() as u64).unwrap();
        let row: Occurrence = serde_json::from_value(serde_json::json!({"occurrence_id":metadata::digest(index.to_string().as_bytes()),"sha256":hash,"size":bytes.len(),"file_type":"text","original_name":"a.txt","original_entry_name":"a.txt","original_stem":"a","original_extension":"txt","source_archive":"","source_path":"source","entry_index":index,"encrypted":false,"ingest_date":if index < 6 {"2026-11-01"} else {"2026-11-02"},"run_id":"original"})).unwrap();
        metadata::store(&repo, &row).unwrap();
    }
}
fn options(source: std::path::PathBuf, output: std::path::PathBuf) -> Options {
    Options {
        sources: vec![source],
        output,
        kind: Kind::Sample(SampleOptions {
            count: Some(3),
            percentage: None,
            seed: 17,
            stratify: vec![],
            unit: SamplingUnit::UniqueHash,
        }),
        dry_run: false,
        resume: false,
    }
}
#[test]
fn hash_default_percentage_strata_and_report_are_reproducible() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fixture(&source);
    let mut o = options(source.clone(), temp.path().join("sample"));
    o.kind = Kind::Sample(SampleOptions {
        count: None,
        percentage: Some(60.0),
        seed: 17,
        stratify: vec![Stratum::IngestDate, Stratum::Family],
        unit: SamplingUnit::UniqueHash,
    });
    let report = derive::run(&o, &Filters::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(report.occurrences, 3);
    assert_eq!(report.unique_objects, 3);
    assert!(o.output.join("reports/dataset.json").is_file());
    assert!(!o.output.join("manifests").exists());
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report.report_paths[0]).unwrap()).unwrap();
    assert_eq!(json["algorithm_version"], "bfsort-dataset-v3");
    assert_eq!(json["selected_occurrence_ids"].as_array().unwrap().len(), 3);
    o.output = temp.path().join("sample2");
    derive::run(&o, &Filters::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(
        serde_json::to_value(metadata::load(&temp.path().join("sample")).unwrap()).unwrap(),
        serde_json::to_value(metadata::load(&o.output).unwrap()).unwrap()
    );
}
#[test]
fn resume_checks_final_snapshot_and_payloads() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fixture(&source);
    let mut o = options(source.clone(), temp.path().join("sample"));
    o.resume = true;
    derive::run(&o, &Filters::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(
        derive::run(&o, &Filters::default(), &AtomicBool::new(false))
            .unwrap()
            .reused_objects,
        3
    );
    let row = metadata::load(&o.output).unwrap().remove(0);
    std::fs::write(
        o.output
            .join("objects")
            .join(&row.sha256[..2])
            .join(&row.sha256),
        vec![b'x'; row.size as usize],
    )
    .unwrap();
    assert!(derive::run(&o, &Filters::default(), &AtomicBool::new(false)).is_err());
    o.output = temp.path().join("other");
    derive::run(&o, &Filters::default(), &AtomicBool::new(false)).unwrap();
    if let Kind::Sample(s) = &mut o.kind {
        s.seed += 1;
    }
    assert!(derive::run(&o, &Filters::default(), &AtomicBool::new(false)).is_err());
}
#[test]
fn invalid_percentage_and_zero_count_are_explicit() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fixture(&source);
    let mut o = options(source, temp.path().join("sample"));
    o.dry_run = true;
    for percentage in [f64::NAN, f64::INFINITY, -1.0, 101.0] {
        o.kind = Kind::Sample(SampleOptions {
            count: None,
            percentage: Some(percentage),
            seed: 0,
            stratify: vec![],
            unit: SamplingUnit::UniqueHash,
        });
        assert!(derive::run(&o, &Filters::default(), &AtomicBool::new(false)).is_err());
    }
    o.kind = Kind::Sample(SampleOptions {
        count: Some(0),
        percentage: None,
        seed: 0,
        stratify: vec![],
        unit: SamplingUnit::Occurrence,
    });
    assert_eq!(
        derive::run(&o, &Filters::default(), &AtomicBool::new(false))
            .unwrap()
            .occurrences,
        0
    );
}

#[test]
fn failed_copy_resumes_verified_objects_and_rejects_changed_source() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fixture(&source);
    let mut rows = metadata::load(&source).unwrap();
    rows.sort_by(|a, b| a.occurrence_id.cmp(&b.occurrence_id));
    let mut seen = std::collections::BTreeSet::new();
    let last = rows
        .iter()
        .filter(|row| seen.insert(row.sha256.clone()))
        .last()
        .unwrap();
    let object = source
        .join("objects")
        .join(&last.sha256[..2])
        .join(&last.sha256);
    let original = std::fs::read(&object).unwrap();
    std::fs::write(&object, vec![b'x'; original.len()]).unwrap();
    let mut o = options(source.clone(), temp.path().join("merged"));
    o.kind = Kind::Merge;
    o.resume = true;
    assert!(derive::run(&o, &Filters::default(), &AtomicBool::new(false)).is_err());
    assert!(!o.output.exists());
    std::fs::write(&object, &original).unwrap();
    let stage = temp.path().join(format!(
        ".bfsort-dataset-{}",
        metadata::digest(o.output.as_os_str().as_encoded_bytes())
    ));
    let staged_object = walkdir::WalkDir::new(stage.join("result/objects"))
        .into_iter()
        .map(|entry| entry.unwrap())
        .find(|entry| entry.file_type().is_file())
        .unwrap()
        .path()
        .to_path_buf();
    let staged_bytes = std::fs::read(&staged_object).unwrap();
    std::fs::write(&staged_object, vec![b'x'; staged_bytes.len()]).unwrap();
    assert!(derive::run(&o, &Filters::default(), &AtomicBool::new(false)).is_err());
    std::fs::write(&staged_object, &staged_bytes).unwrap();
    let result = derive::run(&o, &Filters::default(), &AtomicBool::new(false)).unwrap();
    assert!(result.reused_objects > 0);
    assert_eq!(result.occurrences, 10);
    // Updating effective source metadata invalidates the existing final checkpoint.
    let repo = Repository::existing(&source).unwrap();
    let mut changed = metadata::load(&source).unwrap();
    changed[0].detection.detector_version = "changed".into();
    repo.with_catalog(|catalog| catalog.update_classifications(&changed))
        .unwrap();
    drop(repo);
    assert!(derive::run(&o, &Filters::default(), &AtomicBool::new(false)).is_err());
}

#[test]
fn proportional_occurrence_allocation_and_empty_split_resume() {
    use bfsort::repository::derive::SplitBy;
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fixture(&source);
    let mut o = options(source.clone(), temp.path().join("sample"));
    o.kind = Kind::Sample(SampleOptions {
        count: Some(3),
        percentage: None,
        seed: 1,
        stratify: vec![Stratum::IngestDate],
        unit: SamplingUnit::Occurrence,
    });
    derive::run(&o, &Filters::default(), &AtomicBool::new(false)).unwrap();
    let rows = metadata::load(&o.output).unwrap();
    assert_eq!(
        rows.iter()
            .filter(|row| row.ingest_date == "2026-11-01")
            .count(),
        2
    );
    assert_eq!(
        rows.iter()
            .filter(|row| row.ingest_date == "2026-11-02")
            .count(),
        1
    );
    o.kind = Kind::Split {
        by: SplitBy::Format,
    };
    o.output = temp.path().join("empty");
    o.resume = true;
    let filters = Filters {
        include_extensions: vec!["absent".into()],
        ..Default::default()
    };
    derive::run(&o, &filters, &AtomicBool::new(false)).unwrap();
    derive::run(&o, &filters, &AtomicBool::new(false)).unwrap();
    std::fs::write(o.output.join("dataset.json"), b"{}").unwrap();
    assert!(derive::run(&o, &filters, &AtomicBool::new(false)).is_err());
}

#[test]
fn percentage_uses_floor_without_early_ratio_rounding() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fixture(&source);
    let repo = Repository::existing(&source).unwrap();
    let row = metadata::load(&source).unwrap().remove(0);
    for index in 10..100 {
        let mut duplicate = row.clone();
        duplicate.entry_index = index;
        duplicate.occurrence_id = metadata::digest(index.to_string().as_bytes());
        metadata::store(&repo, &duplicate).unwrap();
    }
    drop(repo);
    let mut o = options(source, temp.path().join("preview"));
    o.dry_run = true;
    o.kind = Kind::Sample(SampleOptions {
        count: None,
        percentage: Some(29.0),
        seed: 0,
        stratify: vec![],
        unit: SamplingUnit::Occurrence,
    });
    assert_eq!(
        derive::run(&o, &Filters::default(), &AtomicBool::new(false))
            .unwrap()
            .occurrences,
        29
    );
}

fn nested_fixture(root: &std::path::Path) -> (Occurrence, Occurrence, Occurrence) {
    use bfsort::{
        detection::classifier::{Family, Format},
        repository::metadata::NestedProvenance,
    };
    fixture(root);
    let repo = Repository::existing(root).unwrap();
    let original = metadata::load(root).unwrap().remove(0);
    let mut parent = original.clone();
    parent.occurrence_id = metadata::digest(b"parent");
    parent.original_extension = "zip".into();
    parent.original_entry_name = "parent.zip".into();
    parent.file_type = "zip".into();
    parent.detection.detected_format = Format::Zip;
    parent.detection.detected_family = Family::Archive;
    let mut middle = parent.clone();
    middle.occurrence_id = metadata::digest(b"middle");
    middle.structural = true;
    middle.nested = Some(NestedProvenance {
        schema_version: 1,
        parent_sha256: parent.sha256.clone(),
        parent_occurrence_id: Some(parent.occurrence_id.clone()),
        root_source: "outer.zip".into(),
        root_input_hash: parent.sha256.clone(),
        archive_depth: 0,
        entry_chain: vec![0],
    });
    let mut child = original;
    child.occurrence_id = metadata::digest(b"child");
    child.original_extension = "pdf".into();
    child.original_entry_name = "child.pdf".into();
    child.nested = Some(NestedProvenance {
        schema_version: 1,
        parent_sha256: middle.sha256.clone(),
        parent_occurrence_id: Some(middle.occurrence_id.clone()),
        root_source: "outer.zip".into(),
        root_input_hash: parent.sha256.clone(),
        archive_depth: 1,
        entry_chain: vec![0, 1],
    });
    metadata::store(&repo, &parent).unwrap();
    metadata::store(&repo, &middle).unwrap();
    metadata::store(&repo, &child).unwrap();
    (parent, middle, child)
}
#[test]
fn nested_selection_keeps_transitive_structural_ancestors_and_resumes() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let (parent, middle, child) = nested_fixture(&source);
    let mut o = options(source, temp.path().join("dataset"));
    if let Kind::Sample(sample) = &mut o.kind {
        sample.count = Some(1);
    }
    o.resume = true;
    let filters = Filters {
        include_extensions: vec!["pdf".into()],
        ..Default::default()
    };
    let report = derive::run(&o, &filters, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.occurrences, 1);
    assert_eq!(report.requested_occurrences, 1);
    assert_eq!(report.ancestry_additions, 2);
    let visible = metadata::load(&o.output).unwrap();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].occurrence_id, child.occurrence_id);
    let all = metadata::load_all(&o.output).unwrap();
    assert_eq!(all.len(), 3);
    for id in [&parent.occurrence_id, &middle.occurrence_id] {
        assert!(
            all.iter()
                .find(|row| &row.occurrence_id == id)
                .unwrap()
                .structural
        );
    }
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(o.output.join("reports/dataset.json")).unwrap())
            .unwrap();
    assert_eq!(json["selected_occurrence_ids"].as_array().unwrap().len(), 1);
    assert_eq!(json["ancestry_occurrence_ids"].as_array().unwrap().len(), 2);
    derive::run(&o, &filters, &AtomicBool::new(false)).unwrap();
}
#[test]
fn split_closes_each_group_and_selected_parent_stays_visible() {
    use bfsort::repository::derive::SplitBy;
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let (parent, _, _) = nested_fixture(&source);
    let mut o = options(source, temp.path().join("dataset"));
    o.kind = Kind::Split {
        by: SplitBy::Extension,
    };
    let filters = Filters {
        include_extensions: vec!["pdf".into(), "zip".into()],
        ..Default::default()
    };
    let report = derive::run(&o, &filters, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.occurrences, 2);
    assert_eq!(report.ancestry_additions, 2);
    let zip = o.output.join("ext-7a6970");
    let pdf = o.output.join("ext-706466");
    assert!(
        !metadata::load(&zip)
            .unwrap()
            .iter()
            .find(|row| row.occurrence_id == parent.occurrence_id)
            .unwrap()
            .structural
    );
    assert_eq!(metadata::load(&pdf).unwrap().len(), 1);
    assert_eq!(metadata::load_all(&pdf).unwrap().len(), 3);
    o.kind = Kind::Merge;
    o.output = temp.path().join("merged");
    let merged = derive::run(&o, &filters, &AtomicBool::new(false)).unwrap();
    assert_eq!(merged.occurrences, 2);
    assert_eq!(merged.ancestry_additions, 1);
    let rows = metadata::load(&o.output).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        !rows
            .iter()
            .find(|row| row.occurrence_id == parent.occurrence_id)
            .unwrap()
            .structural
    );
    assert_eq!(metadata::load_all(&o.output).unwrap().len(), 3);
}
#[test]
fn missing_and_cyclic_nested_parents_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let (parent, _middle, _) = nested_fixture(&source);
    let mut o = options(source.clone(), temp.path().join("dataset"));
    o.kind = Kind::Merge;
    o.dry_run = true;
    let database = source.join("metadata.sqlite3");
    let connection = rusqlite::Connection::open(database).unwrap();
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection
        .execute(
            "DELETE FROM occurrences WHERE id=?1",
            [&parent.occurrence_id],
        )
        .unwrap();
    assert!(derive::run(&o, &Filters::default(), &AtomicBool::new(false)).is_err());
    drop(connection);
    // A fully consistent FK cycle must also be refused, rather than looping.
    let source2 = temp.path().join("cycle");
    let (parent, middle, _) = nested_fixture(&source2);
    let connection = rusqlite::Connection::open(source2.join("metadata.sqlite3")).unwrap();
    connection
        .execute(
            "INSERT INTO ancestry(occurrence_id,parent_id,parent_hash,nested_version,root_source,
            root_input_hash,archive_depth,entry_chain) VALUES(?1,?2,?3,1,'cycle',?3,0,'[0]')",
            rusqlite::params![parent.occurrence_id, middle.occurrence_id, middle.sha256],
        )
        .unwrap();
    drop(connection);
    o.sources = vec![source2];
    assert!(derive::run(&o, &Filters::default(), &AtomicBool::new(false)).is_err());
}

#[test]
fn external_outer_root_needs_no_invented_occurrence() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let (_, _, child) = nested_fixture(&source);
    let connection = rusqlite::Connection::open(source.join("metadata.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE ancestry SET parent_id=NULL,parent_hash=?1,root_input_hash=?1,
            archive_depth=0,entry_chain='[1]' WHERE occurrence_id=?2",
            rusqlite::params![metadata::digest(b"external input"), child.occurrence_id],
        )
        .unwrap();
    drop(connection);
    let mut o = options(source, temp.path().join("dataset"));
    o.kind = Kind::Merge;
    let report = derive::run(
        &o,
        &Filters {
            include_extensions: vec!["pdf".into()],
            ..Default::default()
        },
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(report.occurrences, 1);
    assert_eq!(report.ancestry_additions, 0);
    assert_eq!(metadata::load_all(&o.output).unwrap().len(), 1);
}

#[test]
fn staged_tombstones_are_rejected_instead_of_hiding_requested_rows() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fixture(&source);
    let mut rows = metadata::load(&source).unwrap();
    rows.sort_by(|a, b| a.occurrence_id.cmp(&b.occurrence_id));
    let mut seen = std::collections::BTreeSet::new();
    let last = rows
        .iter()
        .filter(|row| seen.insert(row.sha256.clone()))
        .last()
        .unwrap();
    let object = source
        .join("objects")
        .join(&last.sha256[..2])
        .join(&last.sha256);
    let original = std::fs::read(&object).unwrap();
    std::fs::write(&object, vec![b'x'; original.len()]).unwrap();
    let mut o = options(source, temp.path().join("dataset"));
    o.kind = Kind::Merge;
    o.resume = true;
    assert!(derive::run(&o, &Filters::default(), &AtomicBool::new(false)).is_err());
    let staged = temp
        .path()
        .join(format!(
            ".bfsort-dataset-{}",
            metadata::digest(o.output.as_os_str().as_encoded_bytes())
        ))
        .join("result");
    // A failed copy can now precede the first batch commit. Model an earlier committed batch.
    let staged_repo = bfsort::repository::storage::Repository::existing(&staged).unwrap();
    let row = rows
        .iter()
        .find(|row| row.sha256 != last.sha256 && staged_repo.object(&row.sha256).unwrap().is_file())
        .unwrap()
        .clone();
    metadata::store(&staged_repo, &row).unwrap();
    drop(staged_repo);
    bfsort::repository::cleanup::remove(
        &staged,
        &Filters {
            sha256: Some(row.sha256),
            ..Default::default()
        },
        false,
        true,
    )
    .unwrap();
    std::fs::write(object, original).unwrap();
    let error = derive::run(&o, &Filters::default(), &AtomicBool::new(false)).unwrap_err();
    assert!(error.to_string().contains("removed records"));
    assert!(!o.output.exists());
}

#[test]
fn duplicate_selected_identity_cannot_hide_conflicting_ancestor_provenance() {
    let temp = tempfile::tempdir().unwrap();
    let left = temp.path().join("left");
    let right = temp.path().join("right");
    nested_fixture(&left);
    let (mut parent, _, _) = nested_fixture(&right);
    parent.source_path = "different archive event".into();
    let connection = rusqlite::Connection::open(right.join("metadata.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE occurrences SET source_path=?1 WHERE id=?2",
            rusqlite::params![parent.source_path, parent.occurrence_id],
        )
        .unwrap();
    drop(connection);
    let mut o = options(left, temp.path().join("dataset"));
    o.sources.push(right);
    o.kind = Kind::Merge;
    o.dry_run = true;
    let error = derive::run(
        &o,
        &Filters {
            include_extensions: vec!["pdf".into()],
            ..Default::default()
        },
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert!(error.to_string().contains("conflicting nested ancestor"));
}
