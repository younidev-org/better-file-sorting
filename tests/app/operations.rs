//! Operation history and retry tests.
//!
//! Check lifecycle transitions, interrupted-run detection, and input selection on
//! retry. Verify that repository history uses SQLite and that saved commands
//! exclude secrets and reject changed settings.

use bfsort::{
    app::config::SecurityMode,
    operations::{self, Guard},
    repository::{catalog, storage::Repository},
};

#[test]
fn lifecycle_retry_and_read_only_status() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    let _repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    let args = vec!["reclassify".into(), root.to_str().unwrap().into()];
    let mut guard = Guard::start(&root, "reclassify", &args).unwrap();
    let rows = operations::status(&root).unwrap();
    assert_eq!(rows[0].state, "running");
    assert!(operations::retry_arguments(&root, &rows[0].id).is_err());
    guard.finish(1).unwrap();
    let rows = operations::status(&root).unwrap();
    assert_eq!(rows[0].state, "failed");
    let retry = operations::retry_arguments(&root, &rows[0].id).unwrap();
    assert!(retry.iter().any(|s| s == "--resume"));
    assert!(operations::retry_arguments(&root, "../bad").is_err());
}

#[test]
fn drop_failure_and_unowned_running_record_is_interrupted() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    let _repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    let args = vec!["reclassify".into(), root.to_str().unwrap().into()];
    drop(Guard::start(&root, "reclassify", &args).unwrap());
    let mut rows = operations::status(&root).unwrap();
    assert_eq!(rows[0].state, "failed");
    rows[0].state = "running".into();
    let record = serde_json::to_string(&rows[0]).unwrap();
    catalog::write(&root)
        .unwrap()
        .put_operation(&rows[0].id, &record)
        .unwrap();
    let before = catalog::read(&root).unwrap().operations().unwrap();
    assert_eq!(operations::status(&root).unwrap()[0].state, "interrupted");
    assert_eq!(catalog::read(&root).unwrap().operations().unwrap(), before);
}

#[test]
fn rejects_secrets_unsupported_commands_and_zip_retry() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    let _repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    for url in [
        "https://user:pass@example.com/",
        "https://example.com/?token=secret",
    ] {
        assert!(Guard::start(&root, "collect", &["collect".into(), url.into()]).is_err());
    }
    assert!(Guard::start(&root, "stats", &["stats".into()]).is_err());
    assert!(
        Guard::start(
            &root,
            "ingest",
            &["ingest".into(), "--unknown-secret".into()]
        )
        .is_err()
    );
    let mut guard = Guard::start(&root, "ingest", &["ingest".into(), "--zip".into()]).unwrap();
    guard.finish(1).unwrap();
    let rows = operations::status(&root).unwrap();
    assert!(operations::retry_arguments(&root, &rows[0].id).is_err());
}

#[test]
fn interruption_retry_link_and_changed_settings() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    let _repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    let config = temp.path().join("settings.toml");
    std::fs::write(&config, "workers = 1\n").unwrap();
    let args = vec![
        "analyze".into(),
        root.to_str().unwrap().into(),
        "--config".into(),
        config.to_str().unwrap().into(),
    ];
    let mut guard = Guard::start(&root, "analyze", &args).unwrap();
    guard.interrupt().unwrap();
    let parent = operations::status(&root).unwrap()[0].id.clone();
    assert_eq!(operations::status(&root).unwrap()[0].state, "interrupted");
    assert!(operations::retry_arguments(&root, &parent).is_ok());
    let mut child = Guard::start(&root, "analyze", &args).unwrap();
    child.set_retry_of(&parent).unwrap();
    child.finish(0).unwrap();
    assert!(
        operations::status(&root)
            .unwrap()
            .iter()
            .any(|r| r.retry_of.as_deref() == Some(&parent))
    );
    std::fs::write(&config, "workers = 2\n").unwrap();
    assert!(operations::retry_arguments(&root, &parent).is_err());
}

#[test]
fn configured_password_is_required_again_and_config_zip_refuses_resume() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    let _repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    let password = temp.path().join("password");
    std::fs::write(&password, "secret\n").unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = temp.path().join("settings.toml");
    std::fs::write(
        &config,
        format!("password_file = {:?}\n", password.to_str().unwrap()),
    )
    .unwrap();
    let args = vec![
        "analyze".into(),
        root.to_str().unwrap().into(),
        "--config".into(),
        config.to_str().unwrap().into(),
    ];
    let mut guard = Guard::start(&root, "analyze", &args).unwrap();
    guard.finish(1).unwrap();
    let id = operations::status(&root).unwrap()[0].id.clone();
    assert!(operations::retry_arguments(&root, &id).is_ok());
    std::fs::remove_file(password).unwrap();
    assert!(operations::retry_arguments(&root, &id).is_err());
    let persisted = catalog::read(&root)
        .unwrap()
        .operations()
        .unwrap()
        .join("\n");
    assert!(!persisted.contains("secret"));
    std::fs::write(&config, "zip = true\n").unwrap();
    let args = vec![
        "ingest".into(),
        "--config".into(),
        config.to_str().unwrap().into(),
    ];
    let mut guard = Guard::start(&root, "ingest", &args).unwrap();
    guard.finish(1).unwrap();
    let rows = operations::status(&root).unwrap();
    let id = &rows.iter().find(|r| r.command == "ingest").unwrap().id;
    assert!(operations::retry_arguments(&root, id).is_err());
}

#[test]
fn recorded_counts_checkpoint_links_and_generic_errors() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    let _repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    let args = vec!["reclassify".into(), root.to_str().unwrap().into()];
    let mut guard = Guard::start(&root, "reclassify", &args).unwrap();
    guard.record_counts(Some(3), 1, 1, 1).unwrap();
    guard.finish(2).unwrap();
    let rows = operations::status(&root).unwrap();
    let counts = rows[0].counts.as_ref().unwrap();
    assert_eq!(
        (
            counts.total,
            counts.completed,
            counts.failed,
            counts.skipped
        ),
        (Some(3), 1, 1, 1)
    );
    assert_eq!(
        rows[0].last_error.as_deref(),
        Some("operation failed; inspect command reports")
    );
    assert_eq!(rows[0].checkpoints, ["reports/reclassification"]);
    assert_eq!(rows[0].app_version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn retry_refuses_changed_rules_referenced_by_unchanged_config() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    let _repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    let rules = temp.path().join("rules.toml");
    std::fs::write(&rules, "# initial rules\n").unwrap();
    let config = temp.path().join("settings.toml");
    let contents = format!("rules = {:?}\n", rules.to_str().unwrap());
    std::fs::write(&config, &contents).unwrap();
    let args = vec![
        "analyze".into(),
        root.to_str().unwrap().into(),
        "--config".into(),
        config.to_str().unwrap().into(),
    ];
    let mut guard = Guard::start(&root, "analyze", &args).unwrap();
    guard.finish(1).unwrap();
    let id = operations::status(&root).unwrap()[0].id.clone();
    assert!(operations::retry_arguments(&root, &id).is_ok());
    std::fs::write(&rules, "# changed rules\n").unwrap();
    assert_eq!(std::fs::read_to_string(config).unwrap(), contents);
    assert!(operations::retry_arguments(&root, &id).is_err());
}

#[test]
fn repository_history_uses_catalog_authority_and_collection_stays_json() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    let _repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    let args = vec!["reclassify".into(), root.to_str().unwrap().into()];
    let mut guard = Guard::start(&root, "reclassify", &args).unwrap();
    guard.finish(0).unwrap();
    assert!(catalog::exists(&root).unwrap());
    let mut record = operations::status(&root).unwrap().remove(0);
    assert_eq!(record.state, "completed");
    record.state = "failed".into();
    let legacy = root
        .join("operations/history")
        .join(format!("{}.json", record.id));
    bfsort::collection::acquisition::save_json(&legacy, &record).unwrap();
    assert_eq!(operations::status(&root).unwrap()[0].state, "completed");
    let collection = temp.path().join("collection");
    let mut guard = Guard::start(&collection, "download", &["download".into()]).unwrap();
    guard.finish(0).unwrap();
    assert!(!catalog::exists(&collection).unwrap());
    let record = operations::status(&collection).unwrap().remove(0);
    assert!(
        collection
            .join("operations/history")
            .join(format!("{}.json", record.id))
            .is_file()
    );
}

#[test]
fn repository_status_does_not_fall_back_when_catalog_is_missing() {
    let temp = tempfile::tempdir().unwrap();
    let collection = temp.path().join("collection");
    let mut guard = Guard::start(&collection, "download", &["download".into()]).unwrap();
    guard.finish(1).unwrap();
    let old = operations::status(&collection).unwrap().remove(0);
    let root = temp.path().join("repo");
    let _repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    bfsort::repository::security::private_dir(&root.join("operations")).unwrap();
    bfsort::repository::security::private_dir(&root.join("operations/history")).unwrap();
    bfsort::collection::acquisition::save_json(
        &root
            .join("operations/history")
            .join(format!("{}.json", old.id)),
        &old,
    )
    .unwrap();
    assert!(operations::status(&root).unwrap().is_empty());
    std::fs::remove_file(root.join(catalog::FILE_NAME)).unwrap();
    assert!(operations::status(&root).is_err());
    let args = vec!["reclassify".into(), root.to_str().unwrap().into()];
    assert!(Guard::start(&root, "reclassify", &args).is_err());
    assert!(!catalog::exists(&root).unwrap());
}

#[test]
fn selected_retry_keeps_flags_and_only_uses_recorded_failed_inputs() {
    use bfsort::operations::InputOutcome;
    use clap::Parser;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    let _repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    let good = temp.path().join("good.txt");
    let bad = temp.path().join("bad.pdf");
    let arbitrary = temp.path().join("new.pdf");
    let pending = temp.path().join("pending.txt");
    for path in [&good, &bad, &arbitrary, &pending] {
        std::fs::write(path, b"hello").unwrap();
    }
    let config = temp.path().join("bfs.toml");
    std::fs::write(
        &config,
        format!("inputs = [{:?}]\n", good.to_str().unwrap()),
    )
    .unwrap();
    let args = vec![
        "ingest".into(),
        good.to_str().unwrap().into(),
        "--include-ext".into(),
        "txt,pdf".into(),
        "--include-ext=bin".into(),
        "-j4".into(),
        "-c".into(),
        config.to_str().unwrap().into(),
        bad.to_str().unwrap().into(),
        config.to_str().unwrap().into(),
    ];
    let mut guard = Guard::start(&root, "ingest", &args).unwrap();
    let id = guard.id().to_owned();
    let mut db = catalog::write(&root).unwrap();
    db.record_input(
        &id,
        &InputOutcome {
            source_path: good.to_str().unwrap().into(),
            state: "completed".into(),
            error: None,
        },
    )
    .unwrap();
    db.record_input(
        &id,
        &InputOutcome {
            source_path: bad.to_str().unwrap().into(),
            state: "failed".into(),
            error: Some("input failed; inspect command reports".into()),
        },
    )
    .unwrap();
    db.record_input(
        &id,
        &InputOutcome {
            source_path: pending.to_str().unwrap().into(),
            state: "pending".into(),
            error: None,
        },
    )
    .unwrap();
    guard.finish(1).unwrap();
    let retry = operations::retry_selected_arguments(&root, &id, true, &[]).unwrap();
    assert!(retry.iter().any(|a| a == "txt,pdf"));
    assert!(retry.iter().any(|a| a == "--include-ext=bin"));
    assert!(retry.iter().any(|a| a == "-j4"));
    let cli = bfsort::app::cli::Cli::try_parse_from(std::iter::once("bfsort".into()).chain(retry))
        .unwrap();
    let bfsort::app::cli::Command::Ingest(args) = cli.command else {
        panic!("expected ingest")
    };
    assert_eq!(args.inputs, vec![bad.clone(), pending]);
    assert_eq!(args.config.as_ref(), Some(&config));
    assert!(args.resume);
    assert!(operations::retry_selected_arguments(&root, &id, false, &[arbitrary]).is_err());
    assert!(
        operations::retry_selected_arguments(&root, &id, true, std::slice::from_ref(&good))
            .is_err()
    );
    assert!(operations::retry_selected_arguments(&root, &id, false, &[good]).is_ok());
    std::fs::write(config, "workers = 5\n").unwrap();
    assert!(operations::retry_selected_arguments(&root, &id, true, &[]).is_err());
}

#[test]
fn selected_retry_respects_end_of_options_and_non_ingest_rejection() {
    use bfsort::operations::InputOutcome;
    use clap::Parser;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    let _repo = Repository::open(&root, SecurityMode::Standard).unwrap();
    let input = temp.path().join("--resume");
    std::fs::write(&input, b"hello").unwrap();
    let args = vec![
        "ingest".into(),
        "--recursive=false".into(),
        "--".into(),
        input.to_str().unwrap().into(),
    ];
    let mut guard = Guard::start(&root, "ingest", &args).unwrap();
    let id = guard.id().to_owned();
    catalog::write(&root)
        .unwrap()
        .record_input(
            &id,
            &InputOutcome {
                source_path: input.to_str().unwrap().into(),
                state: "interrupted".into(),
                error: None,
            },
        )
        .unwrap();
    guard.finish(130).unwrap();
    let retry = operations::retry_selected_arguments(&root, &id, true, &[]).unwrap();
    let cli = bfsort::app::cli::Cli::try_parse_from(std::iter::once("bfsort".into()).chain(retry))
        .unwrap();
    let bfsort::app::cli::Command::Ingest(args) = cli.command else {
        panic!("expected ingest")
    };
    assert_eq!(args.inputs, vec![input]);
    assert_eq!(args.recursive, Some(false));
    assert!(args.resume);
    let mut other = Guard::start(
        &root,
        "reclassify",
        &["reclassify".into(), root.to_str().unwrap().into()],
    )
    .unwrap();
    other.finish(1).unwrap();
    assert!(operations::retry_selected_arguments(&root, other.id(), true, &[]).is_err());
}
