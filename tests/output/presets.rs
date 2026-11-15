//! Built-in layouts, ZIP export naming, and publication recovery tests.
//!
//! Check compact export reports and recovery after interruption or tampering.
//! Exercise automatic grouping, payload suffix selection, and mismatch report formats.

use crate::common;
use bfsort::organization::rules::{Preset, Rules};
#[test]
fn embedded_presets_and_exports_keep_report_without_record_indexes() {
    let t = tempfile::tempdir().unwrap();
    let input = t.path().join("mixed.zip");
    let root = t.path().join("repo");
    common::archive(
        &input,
        &[
            ("a.PDF", b"%PDF-1.7\n"),
            ("same.pdf", b"%PDF-1.7\n"),
            ("other.bin", b"%PDF-1.7\n"),
        ],
    );
    assert!(
        common::run(&[
            "ingest".as_ref(),
            input.as_os_str(),
            "-o".as_ref(),
            root.as_os_str(),
            "--security-mode".as_ref(),
            "standard".as_ref()
        ])
        .status
        .success()
    );
    let records = bfsort::repository::metadata::load(&root).unwrap();
    for (preset, expected) in [
        (Preset::ByFormat, "pdf"),
        (Preset::ByExtension, "bin"),
        (Preset::ByMismatch, "compatible"),
    ] {
        let rules = Rules::for_preset(preset);
        let plan = rules.plan(&records).unwrap();
        assert_eq!(plan.len(), 3);
        assert!(
            plan.iter()
                .any(|r| r.path.starts_with(&format!("{expected}/")))
        );
    }
    let output = t.path().join("exports");
    let result = common::run(&[
        "export".as_ref(),
        root.as_os_str(),
        "--preset".as_ref(),
        "by-format".as_ref(),
        "-o".as_ref(),
        output.as_os_str(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut zip =
        zip::ZipArchive::new(std::fs::File::open(output.join("archive.zip")).unwrap()).unwrap();
    let master = rusqlite::Connection::open_with_flags(
        output.join("export.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let entries: i64 = master
        .query_row(
            "SELECT count(*) FROM entries WHERE archive_path = 'archive.zip'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(entries, 3);
    let header: serde_json::Value =
        serde_json::from_reader(zip.by_name("export.json").unwrap()).unwrap();
    assert_eq!(header["schema_version"], 3);
    assert_eq!(header["payload_entries"], 3);
    assert_eq!(header["occurrences"], 3);
    assert_eq!(header["unique_objects"], 1);
    assert_eq!(header["layout_fingerprint"].as_str().unwrap().len(), 64);
    assert_eq!(header["snapshot_fingerprint"].as_str().unwrap().len(), 64);
    assert!(zip.by_name("manifest.jsonl").is_err());
    assert!(zip.by_name("layout.jsonl").is_err());
    let mut index = tempfile::NamedTempFile::new().unwrap();
    std::io::copy(
        &mut zip.by_name("export.sqlite3").unwrap(),
        index.as_file_mut(),
    )
    .unwrap();
    let db = rusqlite::Connection::open_with_flags(
        index.path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let entries: i64 = db.query_row(
        "SELECT count(*) FROM entries WHERE detected_format='pdf' AND mime_type='application/pdf'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(entries, 3);
    assert_eq!(zip.len(), 5);
}

#[test]
fn resume_export_skips_verified_archives_and_rejects_tampering_or_changed_plan() {
    let t = tempfile::tempdir().unwrap();
    let input = t.path().join("a.zip");
    let root = t.path().join("repo");
    let out = t.path().join("exports");
    common::archive(&input, &[("a.pdf", b"%PDF-1.7\n"), ("b.txt", b"hello")]);
    assert!(
        common::run(&[
            "ingest".as_ref(),
            input.as_os_str(),
            "-o".as_ref(),
            root.as_os_str(),
            "--security-mode".as_ref(),
            "standard".as_ref()
        ])
        .status
        .success()
    );
    let args = [
        "export".as_ref(),
        root.as_os_str(),
        "--preset".as_ref(),
        "by-format".as_ref(),
        "--zip-each-dir".as_ref(),
        "-o".as_ref(),
        out.as_os_str(),
        "--resume".as_ref(),
    ];
    let first = common::run(&args);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let pdf = out.join("pdf.zip");
    let before = std::fs::metadata(&pdf).unwrap().modified().unwrap();
    assert!(common::run(&args).status.success());
    assert_eq!(before, std::fs::metadata(&pdf).unwrap().modified().unwrap());
    std::fs::remove_file(out.join("text.zip")).unwrap();
    let missing = common::run(&args);
    assert!(
        missing.status.success(),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );
    assert_eq!(before, std::fs::metadata(&pdf).unwrap().modified().unwrap());
    let checkpoint = std::fs::read_dir(root.join("operations/export"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&checkpoint).unwrap()).unwrap();
    state["archives"]
        .as_object_mut()
        .unwrap()
        .remove("text.zip");
    state["completed"] = false.into();
    let text_before = std::fs::read(out.join("text.zip")).unwrap();
    let index = out.join("export.sqlite3");
    let index_before = std::fs::read(&index).unwrap();
    std::fs::remove_file(&index).unwrap();
    std::fs::write(&checkpoint, serde_json::to_vec(&state).unwrap()).unwrap();
    let retry = common::run(&args);
    assert!(
        retry.status.success(),
        "{}",
        String::from_utf8_lossy(&retry.stderr)
    );
    assert_eq!(std::fs::read(out.join("text.zip")).unwrap(), text_before);
    assert_eq!(std::fs::read(&index).unwrap(), index_before);
    assert_eq!(before, std::fs::metadata(&pdf).unwrap().modified().unwrap());
    let changed = common::run(&[
        "export".as_ref(),
        root.as_os_str(),
        "--preset".as_ref(),
        "by-extension".as_ref(),
        "--zip-each-dir".as_ref(),
        "-o".as_ref(),
        out.as_os_str(),
        "--resume".as_ref(),
    ]);
    assert!(!changed.status.success());
    std::fs::write(&pdf, b"tampered").unwrap();
    let tampered = common::run(&args);
    assert!(!tampered.status.success());
    assert_eq!(std::fs::read(&pdf).unwrap(), b"tampered");
    std::fs::write(&index, b"modified index").unwrap();
    let result = common::run(&args);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("collection index changed"));
    assert_eq!(std::fs::read(index).unwrap(), b"modified index");
}

#[test]
fn crash_recovery_rejects_corrupted_export_report() {
    use std::io::{Read, Write};
    let t = tempfile::tempdir().unwrap();
    let input = t.path().join("a.zip");
    let root = t.path().join("repo");
    let out = t.path().join("out");
    common::archive(&input, &[("a.pdf", b"%PDF-1.7\n")]);
    assert!(
        common::run(&[
            "ingest".as_ref(),
            input.as_os_str(),
            "-o".as_ref(),
            root.as_os_str(),
            "--security-mode".as_ref(),
            "standard".as_ref()
        ])
        .status
        .success()
    );
    let args = [
        "export".as_ref(),
        root.as_os_str(),
        "--zip-each-dir".as_ref(),
        "-o".as_ref(),
        out.as_os_str(),
        "--resume".as_ref(),
    ];
    assert!(common::run(&args).status.success());
    let state_path = std::fs::read_dir(root.join("operations/export"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    state["archives"].as_object_mut().unwrap().clear();
    state["completed"] = false.into();
    std::fs::write(state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let path = out.join("pdf.zip");
    let mut archive = zip::ZipArchive::new(std::fs::File::open(&path).unwrap()).unwrap();
    let mut entries = vec![];
    for i in 0..archive.len() {
        let mut e = archive.by_index(i).unwrap();
        let name = e.name().unwrap().into_owned();
        let mut b = vec![];
        e.read_to_end(&mut b).unwrap();
        entries.push((name, b));
    }
    drop(archive);
    let mut writer = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    for (name, bytes) in entries {
        writer
            .start_file(&name, zip::write::SimpleFileOptions::default())
            .unwrap();
        let bytes = if name == "export.json" {
            let mut report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            report["layout_fingerprint"] = "bogus".into();
            serde_json::to_vec(&report).unwrap()
        } else {
            bytes
        };
        writer.write_all(&bytes).unwrap();
    }
    writer.finish().unwrap();
    let result = common::run(&args);
    assert!(!result.status.success(), "corrupted report was accepted");
}

#[test]
fn format_grouping_exports_mime_types_without_filename_fallback() {
    let t = tempfile::tempdir().unwrap();
    let input = t.path().join("mixed.zip");
    common::archive(
        &input,
        &[
            ("fake.foo", b"%PDF-1.7\n"),
            ("a.NEWTYPE", b"\0\xff\x01"),
            ("b.newtype", b"\0\xff\x01"),
            ("unknown", b"\0\xfe"),
            (
                "vector.foo",
                b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>",
            ),
            ("weak.xyz", b"ordinary prose"),
            ("conflict.bin", b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR %PDF-1.7\n"),
        ],
    );
    let root = t.path().join("repo");
    let ingest = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "-o".as_ref(),
        root.as_os_str(),
        "--security-mode".as_ref(),
        "standard".as_ref(),
        "--preset".as_ref(),
        "by-format".as_ref(),
    ]);
    assert!(
        ingest.status.success(),
        "{}",
        String::from_utf8_lossy(&ingest.stderr)
    );
    let output = t.path().join("automatic");
    let args = [
        "export".as_ref(),
        root.as_os_str(),
        "--preset".as_ref(),
        "by-format".as_ref(),
        "--zip-each-dir".as_ref(),
        "--output".as_ref(),
        output.as_os_str(),
        "--resume".as_ref(),
    ];
    let result = common::run(&args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for (group, count) in [
        ("pdf", 1),
        ("undetected", 3),
        ("mime/image/svg+xml", 1),
        ("text", 1),
        ("png", 1),
    ] {
        let mut zip =
            zip::ZipArchive::new(std::fs::File::open(output.join(format!("{group}.zip"))).unwrap())
                .unwrap();
        let report: serde_json::Value =
            serde_json::from_reader(zip.by_name("export.json").unwrap()).unwrap();
        assert_eq!(report["payload_entries"], count);
        assert!(zip.by_name("manifest.jsonl").is_err());
    }
    assert!(common::run(&args).status.success());
    let query = common::run(&[
        "query".as_ref(),
        root.as_os_str(),
        "--include-mime".as_ref(),
        "IMAGE/SVG+XML".as_ref(),
        "--count".as_ref(),
    ]);
    assert!(query.status.success());
    let count: serde_json::Value = serde_json::from_slice(&query.stdout).unwrap();
    assert_eq!(count["occurrences"], 1);
    let stats = common::run(&["stats".as_ref(), root.as_os_str()]);
    let stats: serde_json::Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(
        stats["by_detected_format"]["image/svg+xml"]["occurrences"],
        1
    );
    assert_eq!(stats["by_detected_format"]["undetected"]["occurrences"], 3);
    let index = rusqlite::Connection::open_with_flags(
        output.join("export.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let format: String = index
        .query_row(
            "SELECT detected_format FROM entries WHERE archive_path = 'mime/image/svg+xml.zip'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(format, "image/svg+xml");
    let rows = bfsort::repository::metadata::load(&root).unwrap();
    let explicit = Rules::parse("[organization]\nduplicates = 'all'\ndefault_directory = 'remainder'\n[[rules]]\nname = 'selected-extension'\n[rules.match]\noriginal_extension = 'newtype'\n[rules.output]\ndirectory = 'my-selection'\nfilename = '{sha256}.sample'\n").unwrap();
    let plan = explicit.plan(&rows).unwrap();
    assert_eq!(
        plan.iter()
            .filter(|p| p.path.starts_with("my-selection/"))
            .count(),
        2
    );
    assert_eq!(plan.len(), 7);
    let both = t.path().join("both.toml");
    std::fs::write(&both, "[organization]\nduplicates = 'all'\ndefault_directory = '{format_group}'\n[[rules]]\nname = 'selected-extension'\n[rules.match]\noriginal_extension = 'newtype'\n[rules.output]\ndirectory = 'my-selection'\nfilename = '{sha256}.sample'\n").unwrap();
    let custom = t.path().join("custom");
    let out = common::run(&[
        "export".as_ref(),
        root.as_os_str(),
        "--rules".as_ref(),
        both.as_os_str(),
        "--zip-each-dir".as_ref(),
        "--output".as_ref(),
        custom.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(custom.join("my-selection.zip").is_file());
    assert!(custom.join("pdf.zip").is_file());
    assert!(custom.join("png.zip").is_file());
    assert!(custom.join("mime/image/svg+xml.zip").is_file());
    let direct = t.path().join("direct");
    let out = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--preset".as_ref(),
        "by-format".as_ref(),
        "--zip-each-dir".as_ref(),
        "--output".as_ref(),
        direct.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(direct.join("pdf.zip").is_file());
    assert!(direct.join("undetected.zip").is_file());
}

#[test]
fn explicit_export_naming_changes_payload_suffixes_without_changing_views() {
    let t = tempfile::tempdir().unwrap();
    let input = t.path().join("mixed.zip");
    let root = t.path().join("repo");
    common::archive(
        &input,
        &[
            ("document.EXE", b"%PDF-1.7\n"),
            ("empty.bin", b"\0\x01\x02"),
        ],
    );
    let result = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--extract".as_ref(),
        "-o".as_ref(),
        root.as_os_str(),
        "--security-mode".as_ref(),
        "standard".as_ref(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let current = std::fs::read(root.join("views/CURRENT")).unwrap();
    for (naming, expected) in [
        ("sample", None),
        ("original", Some("pdf/document.exe")),
        ("detected", Some("pdf/document.pdf")),
    ] {
        let output = t.path().join(format!("{naming}.zip"));
        let result = common::run(&[
            "export".as_ref(),
            root.as_os_str(),
            "--naming".as_ref(),
            naming.as_ref(),
            "-o".as_ref(),
            output.as_os_str(),
        ]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let mut zip = zip::ZipArchive::new(std::fs::File::open(output).unwrap()).unwrap();
        if let Some(expected) = expected {
            assert!(zip.by_name(expected).is_ok());
        } else {
            assert!(zip.file_names().all(|name| {
                name.is_ok_and(|name| {
                    name.ends_with(".sample")
                        || matches!(name.as_ref(), "export.json" | "export.sqlite3")
                })
            }));
        }
        assert!(zip.by_name("layout.jsonl").is_err());
        assert!(zip.by_name("manifest.jsonl").is_err());
        assert_eq!(zip.len(), 4);
        assert_eq!(std::fs::read(root.join("views/CURRENT")).unwrap(), current);
    }
    let generation = String::from_utf8(current).unwrap();
    assert!(
        !root
            .join("views")
            .join(generation.trim())
            .join("layout.jsonl")
            .exists()
    );
    let plan = bfsort::repository::catalog::read(&root)
        .unwrap()
        .view_plan(generation.trim())
        .unwrap();
    assert!(plan.iter().all(|p| p.path.ends_with(".sample")));
}

#[test]
fn reports_keep_table_json_and_csv_without_jsonl_output() {
    use bfsort::app::cli::Cli;
    use clap::Parser;
    for format in ["table", "json", "csv"] {
        assert!(
            Cli::try_parse_from(["bfsort", "report", "mismatches", "--format", format]).is_ok()
        );
    }
    assert!(Cli::try_parse_from(["bfsort", "report", "mismatches", "--format", "jsonl"]).is_err());
}
