//! Independent repository derivation and publication tests.
//!
//! Verify that sample, split, and merge preserve identities and create independent
//! storage. Check failures for overlapping paths, corrupt objects, and conflicting
//! metadata before the destination is published.

#![cfg(unix)]
use bfsort::{
    app::config::SecurityMode,
    repository::{
        derive::{self, Kind, Options, SampleOptions, SamplingUnit},
        metadata::{self, Occurrence},
        storage::Repository,
    },
    selection::Filters,
};
use std::{io::Write, sync::atomic::AtomicBool};

fn source(path: &std::path::Path, mode: SecurityMode) {
    source_with(path, mode, |_| {});
}

fn source_with(path: &std::path::Path, mode: SecurityMode, change: impl FnOnce(&mut [Occurrence])) {
    let repo = Repository::open(path, mode).unwrap();
    let mut records = Vec::new();
    for index in 0..3 {
        let mut file = tempfile::NamedTempFile::new_in(repo.staging()).unwrap();
        file.write_all(b"abc").unwrap();
        repo.commit(file, &metadata::digest(b"abc"), 3).unwrap();
        let record: Occurrence = serde_json::from_value(serde_json::json!({
            "occurrence_id": metadata::digest(index.to_string().as_bytes()), "sha256": metadata::digest(b"abc"),
            "size": 3, "file_type": "text", "original_name": "a.txt", "original_entry_name": "a.txt",
            "original_stem": "a", "original_extension": "txt", "source_archive": "", "source_path": "a",
            "entry_index": index, "encrypted": false, "ingest_date": "2026-11-05", "run_id": "original"
        })).unwrap();
        records.push(record);
    }
    change(&mut records);
    metadata::store_many(&repo, &records).unwrap();
}

#[test]
fn seeded_sample_is_independent_and_reproducible() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("source");
    source(&input, SecurityMode::Standard);
    for name in ["a", "b"] {
        let report = derive::run(
            &Options {
                sources: vec![input.clone()],
                output: dir.path().join(name),
                kind: Kind::Sample(SampleOptions {
                    count: Some(2),
                    percentage: None,
                    seed: 7,
                    stratify: vec![],
                    unit: SamplingUnit::Occurrence,
                }),
                dry_run: false,
                resume: false,
            },
            &Filters::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(report.occurrences, 2);
        assert_eq!(report.unique_objects, 1);
    }
    assert_eq!(
        serde_json::to_value(metadata::load(&dir.path().join("a")).unwrap()).unwrap(),
        serde_json::to_value(metadata::load(&dir.path().join("b")).unwrap()).unwrap()
    );
    use std::os::unix::fs::MetadataExt;
    let object = format!(
        "objects/{}/{}",
        &metadata::digest(b"abc")[..2],
        metadata::digest(b"abc")
    );
    assert_ne!(
        std::fs::metadata(input.join(&object)).unwrap().ino(),
        std::fs::metadata(dir.path().join("a").join(object))
            .unwrap()
            .ino()
    );
}

#[test]
fn sealed_preview_and_failed_copy_leave_destination_absent() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("source");
    source(&input, SecurityMode::Sealed);
    let mut options = Options {
        sources: vec![input],
        output: dir.path().join("dest"),
        kind: Kind::Merge,
        dry_run: true,
        resume: false,
    };
    assert_eq!(
        derive::run(&options, &Filters::default(), &AtomicBool::new(false))
            .unwrap()
            .occurrences,
        3
    );
    assert!(!options.output.exists());
    options.dry_run = false;
    assert!(derive::run(&options, &Filters::default(), &AtomicBool::new(false)).is_err());
    assert!(!options.output.exists());
}

#[test]
fn corruption_and_overlapping_paths_are_rejected_without_publication() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("source");
    source(&input, SecurityMode::Standard);
    let mut options = Options {
        sources: vec![input.clone()],
        output: input.join("inside"),
        kind: Kind::Merge,
        dry_run: true,
        resume: false,
    };
    assert!(derive::run(&options, &Filters::default(), &AtomicBool::new(false)).is_err());
    options.output = dir.path().join("dest");
    options.dry_run = false;
    let hash = metadata::digest(b"abc");
    std::fs::write(input.join("objects").join(&hash[..2]).join(hash), b"bad").unwrap();
    assert!(derive::run(&options, &Filters::default(), &AtomicBool::new(false)).is_err());
    assert!(!options.output.exists());
    assert!(Repository::existing(&input).is_ok());
}

#[test]
fn split_publishes_independent_groups_and_never_overwrites() {
    use bfsort::repository::derive::SplitBy;
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("source");
    source(&input, SecurityMode::Standard);
    let options = Options {
        sources: vec![input],
        output: dir.path().join("groups"),
        kind: Kind::Split {
            by: SplitBy::Extension,
        },
        dry_run: false,
        resume: false,
    };
    let report = derive::run(&options, &Filters::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(report.groups.len(), 1);
    let repo = Repository::existing(&options.output.join(&report.groups[0].name)).unwrap();
    assert_eq!(metadata::load(repo.root()).unwrap().len(), 3);
    assert!(derive::run(&options, &Filters::default(), &AtomicBool::new(false)).is_err());
}

#[test]
fn conflicting_occurrence_ids_fail_and_identical_records_deduplicate() {
    let dir = tempfile::tempdir().unwrap();
    let left = dir.path().join("left");
    let right = dir.path().join("right");
    source(&left, SecurityMode::Standard);
    source(&right, SecurityMode::Standard);
    let mut options = Options {
        sources: vec![right.clone(), left],
        output: dir.path().join("dest"),
        kind: Kind::Merge,
        dry_run: true,
        resume: false,
    };
    assert_eq!(
        derive::run(&options, &Filters::default(), &AtomicBool::new(false))
            .unwrap()
            .occurrences,
        3
    );
    let conflicting = dir.path().join("conflicting");
    source_with(&conflicting, SecurityMode::Standard, |records| {
        records[0].source_path = "different".into();
    });
    options.sources[0] = conflicting;
    assert!(derive::run(&options, &Filters::default(), &AtomicBool::new(false)).is_err());
    assert!(!options.output.exists());
}

#[test]
fn oversized_samples_and_non_archive_ancestors_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("source");
    source_with(&input, SecurityMode::Standard, |records| {
        records[0].nested = Some(metadata::NestedProvenance {
            schema_version: 1,
            parent_sha256: records[1].sha256.clone(),
            parent_occurrence_id: Some(records[1].occurrence_id.clone()),
            root_source: "source.zip".to_owned(),
            root_input_hash: records[1].sha256.clone(),
            archive_depth: 0,
            entry_chain: vec![0],
        });
    });
    let mut options = Options {
        sources: vec![input.clone()],
        output: dir.path().join("dest"),
        kind: Kind::Sample(SampleOptions {
            count: Some(4),
            percentage: None,
            seed: 0,
            stratify: vec![],
            unit: SamplingUnit::Occurrence,
        }),
        dry_run: true,
        resume: false,
    };
    let error = derive::run(&options, &Filters::default(), &AtomicBool::new(false)).unwrap_err();
    assert!(error.to_string().contains("eligible population"));
    options.kind = Kind::Merge;
    let error = derive::run(&options, &Filters::default(), &AtomicBool::new(false)).unwrap_err();
    assert!(error.to_string().contains("ZIP container"));
    assert!(!options.output.exists());
}

#[test]
fn wrong_object_size_fails_even_in_metadata_preview() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("source");
    source(&input, SecurityMode::Standard);
    let hash = metadata::digest(b"abc");
    std::fs::write(
        input.join("objects").join(&hash[..2]).join(hash),
        b"truncated or extended",
    )
    .unwrap();
    let options = Options {
        sources: vec![input],
        output: dir.path().join("dest"),
        kind: Kind::Merge,
        dry_run: true,
        resume: false,
    };
    let error = derive::run(&options, &Filters::default(), &AtomicBool::new(false)).unwrap_err();
    assert!(error.to_string().contains("size mismatch"));
    assert!(!options.output.exists());
}
