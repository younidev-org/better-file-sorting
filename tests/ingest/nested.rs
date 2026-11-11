use crate::common::{archive, run};
use std::fs;

#[test]
fn nested_analysis_preserves_parents_and_reuses_archives() {
    let temp = tempfile::tempdir().unwrap();
    let child = temp.path().join("child.zip");
    archive(&child, &[("payload.pdf", b"%PDF-1.7\nfixture")]);
    let bytes = fs::read(&child).unwrap();
    let root = temp.path().join("root.zip");
    archive(&root, &[("one.bin", &bytes), ("two.zip", &bytes)]);
    let config = temp.path().join("nested.toml");
    fs::write(&config, "input_mode = 'archives'\n[security]\nmode = 'standard'\n[archive]\nnested_extraction = true\nmax_depth = 2\nmax_total_entries = 20\nmax_total_expanded_bytes = '1 MiB'\n").unwrap();
    let repo = temp.path().join("repo");
    let output = run(&[
        "ingest".as_ref(),
        root.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "--output".as_ref(),
        repo.as_os_str(),
        "--resume".as_ref(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records = bfsort::repository::metadata::load(&repo).unwrap();
    assert_eq!(records.len(), 4);
    let children: Vec<_> = records
        .iter()
        .filter(|r| r.original_name == "payload.pdf")
        .collect();
    assert_eq!(children.len(), 2);
    let values: Vec<_> = children
        .iter()
        .map(|r| serde_json::to_value(r).unwrap())
        .collect();
    assert_ne!(
        values[0]["nested"]["parent_occurrence_id"],
        values[1]["nested"]["parent_occurrence_id"]
    );
    let rerun = run(&[
        "ingest".as_ref(),
        root.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "--output".as_ref(),
        repo.as_os_str(),
        "--resume".as_ref(),
    ]);
    assert!(
        rerun.status.success(),
        "{}",
        String::from_utf8_lossy(&rerun.stderr)
    );
    assert_eq!(bfsort::repository::metadata::load(&repo).unwrap().len(), 4);
    let report: serde_json::Value = serde_json::from_slice(&rerun.stdout).unwrap();
    assert_eq!(report["nested"]["metrics"]["extracted_archives"], 0);
    assert_eq!(report["nested"]["metrics"]["reused_archives"], 3);
    assert_eq!(report["accepted"], 0);
    assert_eq!(report["reused_occurrences"], 4);
}

#[test]
fn analyze_existing_repository_without_original_source() {
    let temp = tempfile::tempdir().unwrap();
    let child = temp.path().join("child.zip");
    archive(&child, &[("a.txt", b"hello")]);
    let root = temp.path().join("root.zip");
    archive(&root, &[("child.zip", &fs::read(&child).unwrap())]);
    let repo = temp.path().join("repo");
    let output = run(&[
        "ingest".as_ref(),
        root.as_os_str(),
        "--output".as_ref(),
        repo.as_os_str(),
        "--security-mode".as_ref(),
        "standard".as_ref(),
    ]);
    assert!(output.status.success());
    fs::remove_file(root).unwrap();
    let config = temp.path().join("nested.toml");
    fs::write(
        &config,
        "input_mode = 'archives'\n[archive]\nnested_extraction = true\nmax_depth = 1\n",
    )
    .unwrap();
    let output = run(&[
        "analyze".as_ref(),
        repo.as_os_str(),
        "--config".as_ref(),
        config.as_os_str(),
        "--resume".as_ref(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(bfsort::repository::metadata::load(&repo).unwrap().len(), 2);
}

#[test]
fn tree_budget_charges_duplicate_receipt_replay_and_preview_is_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let child = temp.path().join("child.zip");
    archive(&child, &[("a.txt", &[b'a'; 100])]);
    let bytes = fs::read(&child).unwrap();
    let root = temp.path().join("root.zip");
    archive(&root, &[("one.zip", &bytes), ("two.zip", &bytes)]);
    let config = temp.path().join("nested.toml");
    fs::write(&config, format!("input_mode = 'archives'\n[security]\nmode = 'standard'\n[archive]\nnested_extraction = true\nmax_depth = 1\nmax_total_expanded_bytes = {}\n", 2 * bytes.len() + 150)).unwrap();
    let repo = temp.path().join("repo");
    let out = run(&[
        "ingest".as_ref(),
        root.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "--output".as_ref(),
        repo.as_os_str(),
    ]);
    assert!(!out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(value["failures"].as_u64().unwrap() > 0);
    let before: Vec<_> = walkdir::WalkDir::new(&repo)
        .into_iter()
        .map(|e| {
            let e = e.unwrap();
            (
                e.path().to_owned(),
                e.metadata().unwrap().modified().unwrap(),
            )
        })
        .collect();
    let out = run(&[
        "analyze".as_ref(),
        repo.as_os_str(),
        "--config".as_ref(),
        config.as_os_str(),
        "--dry-run".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after: Vec<_> = walkdir::WalkDir::new(&repo)
        .into_iter()
        .map(|e| {
            let e = e.unwrap();
            (
                e.path().to_owned(),
                e.metadata().unwrap().modified().unwrap(),
            )
        })
        .collect();
    assert_eq!(before, after);
}

#[test]
fn nested_configuration_rejects_contradictory_depths() {
    for text in [
        "nested_extraction = true\nmax_depth = 0",
        "nested_extraction = false\nmax_depth = 1",
        "nested_extraction = true\nmax_depth = 1\nmax_total_entries = 0",
    ] {
        let config = toml::from_str::<bfsort::app::config::Config>(&format!(
            "input_mode = 'archives'\n[archive]\n{text}"
        ));
        assert!(config.is_err() || config.unwrap().validate().is_err());
    }
}

#[cfg(unix)]
#[test]
fn password_retry_reuses_completed_siblings_and_never_persists_secrets() {
    use std::{io::Write, os::unix::fs::PermissionsExt};
    let temp = tempfile::tempdir().unwrap();
    let good = temp.path().join("good.zip");
    archive(&good, &[("good.txt", b"good")]);
    let encrypted = temp.path().join("encrypted.zip");
    let mut zip = zip::ZipWriter::new(fs::File::create(&encrypted).unwrap());
    zip.start_file(
        "private.txt",
        zip::write::SimpleFileOptions::default()
            .with_aes_encryption(zip::AesMode::Aes256, "nested-fixture-password"),
    )
    .unwrap();
    zip.write_all(b"private fixture").unwrap();
    zip.finish().unwrap();
    let root = temp.path().join("root.zip");
    archive(
        &root,
        &[
            ("good.zip", &fs::read(good).unwrap()),
            ("encrypted.zip", &fs::read(encrypted).unwrap()),
        ],
    );
    let passwords = temp.path().join("passwords");
    fs::write(&passwords, "wrong-fixture\n").unwrap();
    fs::set_permissions(&passwords, fs::Permissions::from_mode(0o600)).unwrap();
    let config = temp.path().join("config.toml");
    fs::write(&config,format!("input_mode = 'archives'\npassword_file = '{}'\n[security]\nmode = 'standard'\n[archive]\nnested_extraction = true\nmax_depth = 1\n", passwords.display())).unwrap();
    let repo = temp.path().join("repo");
    let args = [
        "ingest".as_ref(),
        root.as_os_str(),
        "--output".as_ref(),
        repo.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "--resume".as_ref(),
    ];
    let out = run(&args);
    assert!(!out.status.success());
    assert_eq!(bfsort::repository::metadata::load(&repo).unwrap().len(), 3);
    fs::write(&passwords, "nested-fixture-password\n").unwrap();
    let out = run(&args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["nested"]["metrics"]["extracted_archives"], 1);
    assert_eq!(report["nested"]["metrics"]["reused_archives"], 2);
    assert_eq!(bfsort::repository::metadata::load(&repo).unwrap().len(), 4);
    for entry in walkdir::WalkDir::new(repo.join("operations")) {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            assert!(
                !fs::read_to_string(entry.path())
                    .unwrap()
                    .contains("nested-fixture-password")
            );
        }
    }
}

#[test]
fn tree_limit_keeps_successfully_extracted_siblings() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root.zip");
    archive(
        &root,
        &[("keep.txt", b"keep"), ("too-large.txt", &[0; 100])],
    );
    let config = temp.path().join("config.toml");
    fs::write(&config,"input_mode = 'archives'\n[security]\nmode = 'standard'\n[archive]\nnested_extraction = true\nmax_depth = 1\nmax_total_expanded_bytes = 10\n").unwrap();
    let repo = temp.path().join("repo");
    let out = run(&[
        "ingest".as_ref(),
        root.as_os_str(),
        "--output".as_ref(),
        repo.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
    ]);
    assert!(!out.status.success());
    let rows = bfsort::repository::metadata::load(&repo).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].original_name, "keep.txt");
}

#[cfg(unix)]
#[test]
fn wide_sealed_archive_uses_bounded_descriptors() {
    let temp = tempfile::tempdir().unwrap();
    let child = temp.path().join("child.zip");
    archive(&child, &[("a.txt", b"hello")]);
    let bytes = fs::read(child).unwrap();
    let names: Vec<_> = (0..200).map(|i| format!("{i}.zip")).collect();
    let entries: Vec<_> = names
        .iter()
        .map(|n| (n.as_str(), bytes.as_slice()))
        .collect();
    let root = temp.path().join("root.zip");
    archive(&root, &entries);
    let config = temp.path().join("config.toml");
    fs::write(
        &config,
        "input_mode = 'archives'\n[archive]\nnested_extraction = true\nmax_depth = 1\n",
    )
    .unwrap();
    let repo = temp.path().join("repo");
    let out = std::process::Command::new("bash")
        .args([
            "-c",
            "ulimit -n 64; exec \"$@\"",
            "fixture",
            env!("CARGO_BIN_EXE_bfsort"),
            "--json",
            "ingest",
        ])
        .arg(root)
        .arg("-c")
        .arg(config)
        .arg("--output")
        .arg(&repo)
        .arg("--workers")
        .arg("1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        bfsort::repository::metadata::load(&repo).unwrap().len(),
        400
    );
}

#[test]
fn incompatible_nested_checkpoints_fail_before_processing() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root.zip");
    archive(&root, &[("a.txt", b"hello")]);
    let config = temp.path().join("config.toml");
    let repo = temp.path().join("repo");
    let settings = |depth| {
        format!(
            "input_mode = 'archives'\n[security]\nmode = 'standard'\n[archive]\nnested_extraction = true\nmax_depth = {depth}\n"
        )
    };
    fs::write(&config, settings(1)).unwrap();
    let args = [
        "ingest".as_ref(),
        root.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "--output".as_ref(),
        repo.as_os_str(),
        "--resume".as_ref(),
    ];
    assert!(run(&args).status.success());
    fs::write(&config, settings(2)).unwrap();
    let out = run(&args);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("checkpoint"));
    fs::write(&config, settings(1)).unwrap();
    let checkpoint = fs::read_dir(repo.join("operations/trees"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
    state["schema_version"] = 999.into();
    fs::write(&checkpoint, serde_json::to_vec(&state).unwrap()).unwrap();
    let out = run(&args);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("checkpoint"));
}

#[test]
fn lowered_budget_checks_completed_branches_before_new_extraction() {
    let temp = tempfile::tempdir().unwrap();
    let good = temp.path().join("good.zip");
    archive(&good, &[("large.txt", &[b'a'; 100])]);
    let pending = temp.path().join("pending.zip");
    archive(&pending, &[("small.txt", b"b")]);
    let root = temp.path().join("root.zip");
    archive(
        &root,
        &[
            ("good.zip", &fs::read(good).unwrap()),
            ("pending.zip", &fs::read(pending).unwrap()),
        ],
    );
    let config = temp.path().join("config.toml");
    let repo = temp.path().join("repo");
    let settings = |limit| {
        format!(
            "input_mode = 'archives'\n[security]\nmode = 'standard'\n[archive]\nnested_extraction = true\nmax_depth = 1\nmax_total_expanded_bytes = {limit}\n"
        )
    };
    fs::write(&config, settings(10000)).unwrap();
    let args = [
        "ingest".as_ref(),
        root.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "--output".as_ref(),
        repo.as_os_str(),
        "--resume".as_ref(),
    ];
    assert!(run(&args).status.success());
    let mut root_bytes = 0;
    for entry in fs::read_dir(repo.join("operations/extraction")).unwrap() {
        let path = entry.unwrap().path();
        let r: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if r["children"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "small.txt")
        {
            fs::remove_file(path).unwrap();
        } else if r["children"].as_array().unwrap().len() == 2 {
            root_bytes = r["bytes"].as_u64().unwrap();
        }
    }
    fs::write(&config, settings(root_bytes + 50)).unwrap();
    let out = run(&args);
    assert!(!out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["nested"]["metrics"]["extracted_archives"], 0);
}

#[test]
fn analysis_after_nested_ingestion_keeps_existing_occurrence_ids() {
    let t = tempfile::tempdir().unwrap();
    let child = t.path().join("child.zip");
    archive(&child, &[("a.txt", b"hello")]);
    let root = t.path().join("root.zip");
    archive(&root, &[("child.zip", &fs::read(child).unwrap())]);
    let config = t.path().join("nested.toml");
    fs::write(&config,"input_mode = 'archives'\n[security]\nmode = 'standard'\n[archive]\nnested_extraction = true\nmax_depth = 1\n").unwrap();
    let repo = t.path().join("repo");
    assert!(
        run(&[
            "ingest".as_ref(),
            root.as_os_str(),
            "-c".as_ref(),
            config.as_os_str(),
            "--output".as_ref(),
            repo.as_os_str()
        ])
        .status
        .success()
    );
    let before = bfsort::repository::metadata::load(&repo).unwrap();
    let out = run(&[
        "analyze".as_ref(),
        repo.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "--resume".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after = bfsort::repository::metadata::load(&repo).unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(
        serde_json::to_value(before).unwrap(),
        serde_json::to_value(after).unwrap()
    );
}

#[test]
fn parallel_roots_coalesce_identical_archive_extraction() {
    let t = tempfile::tempdir().unwrap();
    let child = t.path().join("child.zip");
    archive(&child, &[("a.txt", b"hello")]);
    let one = t.path().join("one.zip");
    let two = t.path().join("two.zip");
    archive(&one, &[("child.zip", &fs::read(child).unwrap())]);
    fs::copy(&one, &two).unwrap();
    let config = t.path().join("nested.toml");
    fs::write(&config,"input_mode = 'archives'\nworkers = 4\n[security]\nmode = 'standard'\n[archive]\nnested_extraction = true\nmax_depth = 1\n").unwrap();
    let repo = t.path().join("repo");
    let out = run(&[
        "ingest".as_ref(),
        one.as_os_str(),
        two.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "--output".as_ref(),
        repo.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["nested"]["metrics"]["extracted_archives"], 2);
    assert_eq!(report["summary"]["occurrences"], 4);
}

#[test]
fn malformed_provenance_depth_is_rejected_before_traversal() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root.zip");
    archive(&root, &[("a.txt", b"hello")]);
    let config = temp.path().join("nested.toml");
    fs::write(
        &config,
        "input_mode = 'archives'\n[archive]\nnested_extraction = true\nmax_depth = 1\n",
    )
    .unwrap();
    let repo = temp.path().join("repo");
    assert!(
        run(&[
            "ingest".as_ref(),
            root.as_os_str(),
            "-c".as_ref(),
            config.as_os_str(),
            "--output".as_ref(),
            repo.as_os_str()
        ])
        .status
        .success()
    );
    let connection =
        rusqlite::Connection::open(repo.join(bfsort::repository::catalog::FILE_NAME)).unwrap();
    let records: Vec<(String, String)> = {
        let mut statement = connection
            .prepare("SELECT id,record FROM occurrences")
            .unwrap();
        statement
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    for (id, text) in records {
        let mut row: serde_json::Value = serde_json::from_str(&text).unwrap();
        row["nested"]["archive_depth"] = usize::MAX.into();
        connection
            .execute(
                "UPDATE occurrences SET record=?1 WHERE id=?2",
                rusqlite::params![row.to_string(), id],
            )
            .unwrap();
    }
    drop(connection);
    assert!(bfsort::repository::metadata::load(&repo).is_err());
}

#[test]
fn filtered_nested_members_preserve_only_structural_zip_ancestry() {
    let t = tempfile::tempdir().unwrap();
    let child = t.path().join("child.zip");
    archive(
        &child,
        &[
            ("keep.pdf", b"%PDF-1.7\nfixture"),
            ("drop.txt", b"excluded text"),
        ],
    );
    let root = t.path().join("root.zip");
    archive(
        &root,
        &[
            ("container.zip", &fs::read(&child).unwrap()),
            ("outer.txt", b"excluded outer text"),
        ],
    );
    let config = t.path().join("nested.toml");
    fs::write(&config,"input_mode='archives'\n[security]\nmode='standard'\n[archive]\nnested_extraction=true\nmax_depth=2\n[filters]\ninclude_extensions=['pdf']\n").unwrap();
    let repo = t.path().join("repo");
    let out = run(&[
        "ingest".as_ref(),
        root.as_os_str(),
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
    let visible = bfsort::repository::metadata::load(&repo).unwrap();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].original_name, "keep.pdf");
    let all = bfsort::repository::metadata::load_all(&repo).unwrap();
    assert_eq!(all.len(), 2);
    let parent = all.iter().find(|r| r.structural).unwrap();
    assert_eq!(
        visible[0]
            .nested
            .as_ref()
            .unwrap()
            .parent_occurrence_id
            .as_ref(),
        Some(&parent.occurrence_id)
    );
    let excluded = bfsort::repository::metadata::digest(b"excluded text");
    assert!(
        !repo
            .join("objects")
            .join(&excluded[..2])
            .join(excluded)
            .exists()
    );
    assert!(!repo.join("manifests").exists());
    let again = run(&[
        "ingest".as_ref(),
        root.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "-o".as_ref(),
        repo.as_os_str(),
        "--resume".as_ref(),
    ]);
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert_eq!(
        bfsort::repository::metadata::load_all(&repo).unwrap().len(),
        2
    );
}

#[test]
fn filtered_members_still_charge_budget_and_filter_changes_reject_resume() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("root.zip");
    archive(
        &root,
        &[
            ("drop.txt", &[b'x'; 128]),
            ("keep.pdf", b"%PDF-1.7\nfixture"),
        ],
    );
    let config = t.path().join("filtered.toml");
    let settings = "input_mode='archives'\n[security]\nmode='standard'\n[archive]\nnested_extraction=true\nmax_depth=1\nmax_total_expanded_bytes=64\n[filters]\ninclude_extensions=['pdf']\n";
    fs::write(&config, settings).unwrap();
    let repo = t.path().join("limited");
    let out = run(&[
        "ingest".as_ref(),
        root.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "-o".as_ref(),
        repo.as_os_str(),
    ]);
    assert!(!out.status.success());
    assert!(
        bfsort::repository::metadata::load(&repo)
            .unwrap()
            .is_empty()
    );
    fs::write(
        &config,
        settings.replace("max_total_expanded_bytes=64\n", ""),
    )
    .unwrap();
    let repo = t.path().join("repo");
    let run_ingest = || {
        run(&[
            "ingest".as_ref(),
            root.as_os_str(),
            "-c".as_ref(),
            config.as_os_str(),
            "-o".as_ref(),
            repo.as_os_str(),
            "--resume".as_ref(),
        ])
    };
    assert!(run_ingest().status.success());
    fs::write(
        &config,
        settings
            .replace("max_total_expanded_bytes=64\n", "")
            .replace("['pdf']", "['txt']"),
    )
    .unwrap();
    let out = run_ingest();
    assert!(!out.status.success());
    let rows = bfsort::repository::metadata::load(&repo).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].original_name, "keep.pdf");
}

#[test]
fn analyze_filters_descendants_without_filtering_existing_root_archives() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("root.zip");
    archive(
        &root,
        &[("keep.pdf", b"%PDF-1.7\nfixture"), ("drop.txt", b"ignored")],
    );
    let repo = t.path().join("repo");
    let out = run(&[
        "ingest".as_ref(),
        root.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "--security-mode".as_ref(),
        "standard".as_ref(),
        "-o".as_ref(),
        repo.as_os_str(),
    ]);
    assert!(out.status.success());
    let config = t.path().join("analyze.toml");
    fs::write(&config,"input_mode='archives'\n[archive]\nnested_extraction=true\nmax_depth=1\n[filters]\ninclude_extensions=['pdf']\n").unwrap();
    let out = run(&[
        "analyze".as_ref(),
        repo.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows = bfsort::repository::metadata::load(&repo).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|r| r.original_name == "keep.pdf"));
    assert!(!rows.iter().any(|r| r.original_name == "drop.txt"));
}

#[test]
fn later_descendant_selection_can_promote_structural_archives() {
    let t = tempfile::tempdir().unwrap();
    let inner = t.path().join("inner.zip");
    archive(&inner, &[("keep.pdf", b"%PDF-1.7\nfixture")]);
    let middle = t.path().join("middle.zip");
    archive(&middle, &[("inner.zip", &fs::read(&inner).unwrap())]);
    let root = t.path().join("root.zip");
    archive(&root, &[("middle.zip", &fs::read(&middle).unwrap())]);
    let config = t.path().join("nested.toml");
    let settings = "input_mode='archives'\n[security]\nmode='standard'\n[archive]\nnested_extraction=true\nmax_depth=2\n[filters]\ninclude_extensions=['pdf']\n";
    fs::write(&config, settings).unwrap();
    let repo = t.path().join("repo");
    let out = run(&[
        "ingest".as_ref(),
        root.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
        "-o".as_ref(),
        repo.as_os_str(),
    ]);
    assert!(out.status.success());
    assert_eq!(bfsort::repository::metadata::load(&repo).unwrap().len(), 1);
    fs::write(&config, settings.replace("['pdf']", "['zip']")).unwrap();
    let out = run(&[
        "analyze".as_ref(),
        repo.as_os_str(),
        "-c".as_ref(),
        config.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows = bfsort::repository::metadata::load_all(&repo).unwrap();
    assert!(
        !rows
            .iter()
            .find(|r| r.original_name == "inner.zip")
            .unwrap()
            .structural
    );
    assert!(
        rows.iter()
            .find(|r| r.original_name == "middle.zip")
            .unwrap()
            .structural
    );
    assert_eq!(bfsort::repository::metadata::load(&repo).unwrap().len(), 2);
}
