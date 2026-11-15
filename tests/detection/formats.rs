//! Linux file(1) classification, extension compatibility, and catalog workflows.

use crate::common;
use bfsort::detection::classifier;

fn pe() -> Vec<u8> {
    let mut b = vec![0; 512];
    b[..2].copy_from_slice(b"MZ");
    b[60..64].copy_from_slice(&128u32.to_le_bytes());
    b[128..132].copy_from_slice(b"PE\0\0");
    b[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
    b[134..136].copy_from_slice(&1u16.to_le_bytes());
    b[148..150].copy_from_slice(&240u16.to_le_bytes());
    b[152..154].copy_from_slice(&0x20bu16.to_le_bytes());
    b
}
fn elf() -> Vec<u8> {
    let mut b = vec![0; 64];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    b[16] = 2;
    b[18] = 62;
    b[20] = 1;
    b[52] = 64;
    b
}
fn classify_bytes(bytes: &[u8]) -> classifier::Detection {
    use std::io::Write;
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    classifier::detect_file(&mut file).unwrap()
}

#[test]
fn mime_results_preserve_specific_types_and_distinguish_generic_data() {
    for (bytes, expected_mime, expected_label) in [
        (b"%PDF-1.7\n".as_slice(), "application/pdf", "pdf"),
        (
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>",
            "image/svg+xml",
            "image/svg+xml",
        ),
        (b"\0\xff\x01", "application/octet-stream", "undetected"),
    ] {
        let detection = classify_bytes(bytes);
        assert_eq!(detection.mime_type.as_deref(), Some(expected_mime));
        assert_eq!(detection.format_label(), expected_label);
    }
}

#[test]
fn extension_compatibility_uses_filename_and_detected_alias_independently() {
    use bfsort::detection::mismatch::{Status, evaluate};
    let pe = classify_bytes(&pe());
    let elf = classify_bytes(&elf());
    let unknown = classify_bytes(b"\0\xff");
    let jpeg = classify_bytes(b"\xff\xd8\xff\xe0\0\x10JFIF\0");
    assert_eq!(evaluate("a.exe", &unknown).status, Status::UnknownFormat);
    assert_eq!(evaluate("a.JPG", &jpeg).status, Status::Match);
    assert_eq!(evaluate("a.jpeg", &jpeg).status, Status::Match);
    for (name, d, status) in [
        ("a.exe", &pe, Status::Match),
        ("a.DLL", &pe, Status::Match),
        ("invoice.exe.pdf", &pe, Status::Mismatch),
        ("a.exe", &elf, Status::Mismatch),
        ("sample", &elf, Status::MissingExtension),
        ("sample.bin", &pe, Status::Compatible),
        ("sample.dat", &elf, Status::Compatible),
        ("a.unregistered", &pe, Status::UnknownExtension),
    ] {
        assert_eq!(evaluate(name, d).status, status, "{name}");
    }
    assert_eq!(bfsort::detection::mismatch::extension("a.PDF.EXE"), "exe");
    assert_eq!(bfsort::detection::mismatch::extension("a.TAR.GZ"), "tar.gz");
}

#[test]
fn ingestion_reports_stats_rules_and_independent_exports() {
    let t = tempfile::tempdir().unwrap();
    let input = t.path().join("input.zip");
    let repo = t.path().join("repo");
    let pe = pe();
    let elf = elf();
    common::archive(
        &input,
        &[
            ("invoice.exe.pdf", &pe),
            ("good.EXE", &pe),
            ("loader.exe", &elf),
            ("sample", &elf),
            ("note.js", b"hello"),
        ],
    );
    let result = common::run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--output".as_ref(),
        repo.as_os_str(),
        "--security-mode".as_ref(),
        "standard".as_ref(),
        "--workers".as_ref(),
        "4".as_ref(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let records = common::manifest(&repo);
    assert_eq!(records.len(), 5);
    assert!(records.iter().all(|r| r["detection"]["detector_version"]
        == bfsort::detection::classifier::FILE_DETECTOR_VERSION));
    let report = common::run(&[
        "report".as_ref(),
        "mismatches".as_ref(),
        repo.as_os_str(),
        "--format".as_ref(),
        "json".as_ref(),
    ]);
    assert!(
        report.status.success(),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(report["rows"].as_array().unwrap().len(), 3);
    assert_eq!(report["counts"]["mismatch"], 3);
    let stats = common::run(&["stats".as_ref(), repo.as_os_str()]);
    let stats: serde_json::Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(stats["occurrences"], 5);
    assert_eq!(stats["unique_samples"], 3);
    assert_eq!(stats["by_detected_format"]["pe"]["occurrences"], 2);
    assert_eq!(stats["by_detected_format"]["pe"]["unique_hashes"], 1);
    std::fs::remove_file(input).unwrap();
    let before = common::manifest(&repo);
    for (field, folder) in [
        ("detected_format", "formats"),
        ("original_extension", "extensions"),
    ] {
        let rules = t.path().join(format!("{folder}.toml"));
        std::fs::write(
            &rules,
            format!("[organization]\ndefault_directory = '{{{field}}}'\n"),
        )
        .unwrap();
        let out = t.path().join(folder);
        let export = common::run(&[
            "export".as_ref(),
            repo.as_os_str(),
            "--rules".as_ref(),
            rules.as_os_str(),
            "--zip-each-dir".as_ref(),
            "--output".as_ref(),
            out.as_os_str(),
        ]);
        assert!(
            export.status.success(),
            "{}",
            String::from_utf8_lossy(&export.stderr)
        );
        assert!(
            out.join(if folder == "formats" {
                "pe.zip"
            } else {
                "pdf.zip"
            })
            .exists()
        );
    }
    assert_eq!(before, common::manifest(&repo));
}

#[test]
fn unevaluated_catalog_records_can_be_reclassified() {
    let t = tempfile::tempdir().unwrap();
    let input = t.path().join("input.zip");
    let repo = t.path().join("repo");
    common::archive(&input, &[("invoice.pdf", &pe())]);
    assert!(
        common::run(&[
            "ingest".as_ref(),
            input.as_os_str(),
            "-o".as_ref(),
            repo.as_os_str(),
            "--security-mode".as_ref(),
            "standard".as_ref()
        ])
        .status
        .success()
    );
    let mut record = bfsort::repository::metadata::load(&repo).unwrap().remove(0);
    record.detection = Default::default();
    record.mismatch = Default::default();
    let repository = bfsort::repository::storage::Repository::existing(&repo).unwrap();
    repository
        .with_catalog(|catalog| catalog.update_classifications(&[record]))
        .unwrap();
    drop(repository);
    let records = bfsort::repository::metadata::load(&repo).unwrap();
    assert_eq!(
        records[0].detection.detected_format,
        classifier::Format::NotEvaluated
    );
    assert_eq!(
        records[0].mismatch.status,
        bfsort::detection::mismatch::Status::NotEvaluated
    );
    let result = common::run(&["reclassify".as_ref(), repo.as_os_str()]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        bfsort::repository::metadata::load(&repo).unwrap()[0]
            .mismatch
            .status,
        bfsort::detection::mismatch::Status::Mismatch
    );
}

#[test]
#[cfg(unix)]
fn encrypted_ingestion_sealed_reports_and_export_refusal() {
    use std::{fs::File, io::Write, os::unix::fs::PermissionsExt};
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("encrypted.zip");
    let repo = t.path().join("repo");
    let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
    zip.start_file(
        "invoice.pdf",
        zip::write::SimpleFileOptions::default()
            .with_aes_encryption(zip::AesMode::Aes256, "fixture"),
    )
    .unwrap();
    zip.write_all(&pe()).unwrap();
    zip.finish().unwrap();
    let password = t.path().join("password.txt");
    std::fs::write(&password, "fixture\n").unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = common::run(&[
        "ingest".as_ref(),
        path.as_os_str(),
        "-o".as_ref(),
        repo.as_os_str(),
        "--password-file".as_ref(),
        password.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hash = common::manifest(&repo)[0]["sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let object = repo.join("objects").join(&hash[..2]).join(&hash);
    for format in ["table", "json", "csv"] {
        let out = common::run(&[
            "report".as_ref(),
            "mismatches".as_ref(),
            repo.as_os_str(),
            "--format".as_ref(),
            format.as_ref(),
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("invoice.pdf"));
    }
    let out = t.path().join("out.zip");
    assert!(
        common::run(&[
            "export".as_ref(),
            repo.as_os_str(),
            "-o".as_ref(),
            out.as_os_str(),
            "--dry-run".as_ref()
        ])
        .status
        .success()
    );
    assert!(!out.exists());
    assert!(
        !common::run(&[
            "export".as_ref(),
            repo.as_os_str(),
            "-o".as_ref(),
            out.as_os_str()
        ])
        .status
        .success()
    );
    assert!(
        !common::run(&["reclassify".as_ref(), repo.as_os_str()])
            .status
            .success()
    );
    assert_eq!(
        std::fs::metadata(object).unwrap().permissions().mode() & 0o777,
        0
    );
}

#[test]
fn report_escaping_filtering_and_new_rule_matchers() {
    let t = tempfile::tempdir().unwrap();
    let input = t.path().join("a.zip");
    let repo = t.path().join("repo");
    common::archive(&input, &[("comma,quote\".pdf", &pe()), ("good.exe", &pe())]);
    assert!(common::ingest(&input, &repo, "2").status.success());
    let records = bfsort::repository::metadata::load(&repo).unwrap();
    let report =
        bfsort::output::report::mismatches(&records, &[], classifier::Confidence::High, false);
    let mut csv = vec![];
    report
        .write(&mut csv, bfsort::output::report::ReportFormat::Csv)
        .unwrap();
    assert!(
        String::from_utf8(csv)
            .unwrap()
            .contains("\"comma,quote\"\".pdf\"")
    );
    let report = bfsort::output::report::mismatches(
        &records,
        &[bfsort::detection::mismatch::Status::Match],
        classifier::Confidence::High,
        false,
    );
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.rows[0].original_entry_name, "good.exe");
    let rules = bfsort::organization::rules::Rules::parse("[[rules]]\nname='mismatch'\n[rules.match]\ndetected_format='pe'\nmismatch_status='mismatch'\n[rules.output]\ndirectory='{detected_family}/{detected_format}/{mismatch_status}'\nfilename='{sha256}.sample'\n[organization]\nduplicates='all'\n").unwrap();
    assert!(
        rules
            .plan(&records)
            .unwrap()
            .iter()
            .any(|p| p.path.starts_with("executable/pe/mismatch/"))
    );
    let out = t.path().join("report.csv");
    let args = [
        "report".as_ref(),
        "mismatches".as_ref(),
        repo.as_os_str(),
        "--format".as_ref(),
        "csv".as_ref(),
        "-o".as_ref(),
        out.as_os_str(),
    ];
    assert!(common::run(&args).status.success());
    let before = std::fs::read(&out).unwrap();
    assert!(!common::run(&args).status.success());
    assert_eq!(before, std::fs::read(out).unwrap());
}

#[test]
fn export_trusts_persisted_metadata_and_never_rehashes_or_reclassifies() {
    use std::io::Read;
    let t = tempfile::tempdir().unwrap();
    let input = t.path().join("a.zip");
    let root = t.path().join("repo");
    common::archive(&input, &[("a.pdf", b"%PDF-1.7\nfixture\n")]);
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
    std::fs::remove_file(input).unwrap();
    let repo = bfsort::repository::storage::Repository::existing(&root).unwrap();
    let records = bfsort::repository::metadata::load(&root).unwrap();
    let pointer = std::fs::read(root.join("views/CURRENT")).unwrap();
    let manifest = common::manifest(&root);
    // Deliberately violate storage integrity to prove export uses neither hashing nor detection.
    let bytes = vec![0xff; records[0].size as usize];
    std::fs::write(repo.object(&records[0].sha256).unwrap(), &bytes).unwrap();
    let config = bfsort::app::config::Config {
        zip: true,
        output: t.path().join("out.zip"),
        ..Default::default()
    };
    let rules = bfsort::organization::rules::Rules::parse(
        "[organization]\ndefault_directory='{detected_format}'\n",
    )
    .unwrap();
    bfsort::output::archive::export_repository(
        &repo,
        &rules,
        &config,
        false,
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    let mut zip = zip::ZipArchive::new(std::fs::File::open(&config.output).unwrap()).unwrap();
    let mut exported = vec![];
    zip.by_name(&format!("pdf/{}.sample", records[0].sha256))
        .unwrap()
        .read_to_end(&mut exported)
        .unwrap();
    assert_eq!(exported, bytes);
    assert_eq!(pointer, std::fs::read(root.join("views/CURRENT")).unwrap());
    assert_eq!(manifest, common::manifest(&root));
}

#[test]
fn partial_reclassification_preserves_unselected_detection_and_writes_no_jsonl() {
    use bfsort::{
        repository::{metadata, storage::Repository},
        selection::Filters,
    };
    let t = tempfile::tempdir().unwrap();
    let inputs = t.path().join("inputs");
    std::fs::create_dir(&inputs).unwrap();
    std::fs::write(inputs.join("one.txt"), b"hello one").unwrap();
    std::fs::write(inputs.join("two.pdf"), b"%PDF-1.7\nfixture").unwrap();
    let root = t.path().join("repo");
    let out = common::run(&[
        "ingest".as_ref(),
        inputs.as_os_str(),
        "--input-mode".as_ref(),
        "files".as_ref(),
        "--security-mode".as_ref(),
        "standard".as_ref(),
        "-o".as_ref(),
        root.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let repo = Repository::existing(&root).unwrap();
    let mut rows = metadata::load(&root).unwrap();
    for row in &mut rows {
        row.detection.detector_version = "stale".into();
    }
    repo.with_catalog(|c| c.update_classifications(&rows))
        .unwrap();
    let filters = Filters {
        include_extensions: vec!["txt".into()],
        ..Default::default()
    };
    assert_eq!(
        metadata::reclassify_selected(
            &repo,
            &std::sync::atomic::AtomicBool::new(false),
            false,
            &filters
        )
        .unwrap(),
        1
    );
    let rows = metadata::load(&root).unwrap();
    assert_eq!(
        rows.iter()
            .find(|r| r.original_extension == "pdf")
            .unwrap()
            .detection
            .detector_version,
        "stale"
    );
    assert_eq!(
        rows.iter()
            .find(|r| r.original_extension == "txt")
            .unwrap()
            .detection
            .detector_version,
        classifier::FILE_DETECTOR_VERSION
    );
    assert!(!root.join("reports/classification.jsonl").exists());
}
