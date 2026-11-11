//! Streaming extraction, private staging, path safety, resource limits, and cancellation.

use bfsort::{app::config::Limits, ingest::extraction::extract};
use std::{fs::File, io::Write, sync::atomic::AtomicBool};
use zip::{ZipWriter, write::SimpleFileOptions};
/// Build an encrypted or plain single-entry ZIP fixture.
fn zip(name: &str, bytes: &[u8], encrypted: bool) -> (tempfile::TempDir, zip::ZipArchive<File>) {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("test.zip");
    let mut w = ZipWriter::new(File::create(&path).unwrap());
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let options = if encrypted {
        options.with_aes_encryption(zip::AesMode::Aes256, "fixture-password")
    } else {
        options
    };
    w.start_file(name, options).unwrap();
    w.write_all(bytes).unwrap();
    w.finish().unwrap();
    let a = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
    (d, a)
}
#[test]
/// Ensure extraction hashes and counts streamed content.
fn stream_hashes_harmless_content() {
    let (d, mut a) = zip("safe.txt", b"abc", false);
    let mut total = 0;
    let item = extract(
        &mut a,
        0,
        &[],
        d.path(),
        &Limits::default(),
        &mut total,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(
        item.sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(item.size, 3);
    assert_eq!(item.prefix, b"abc");
    assert_eq!(total, 3);
}
#[test]
/// Ensure AES extraction retries passwords and rejects wrong candidates.
fn aes_retries_candidates_and_checks_integrity() {
    let (d, mut a) = zip("safe.txt", b"abc", true);
    let mut total = 0;
    assert!(
        extract(
            &mut a,
            0,
            &["wrong".into()],
            d.path(),
            &Limits::default(),
            &mut total,
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    let item = extract(
        &mut a,
        0,
        &["wrong".into(), "fixture-password".into()],
        d.path(),
        &Limits::default(),
        &mut total,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(item.size, 3);
}
#[test]
/// Ensure hostile names, limits, and cancellation clean up staging.
fn hostile_names_limits_and_interruptions_leave_no_staging_files() {
    for name in ["../escape", "/absolute", "C:\\escape", "a\\..\\escape"] {
        let (d, mut a) = zip(name, b"abc", false);
        assert!(
            extract(
                &mut a,
                0,
                &[],
                d.path(),
                &Limits::default(),
                &mut 0,
                &AtomicBool::new(false)
            )
            .is_err(),
            "{name}"
        );
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    }
    let (d, mut a) = zip("safe", b"abc", false);
    let limits = Limits {
        max_entry_bytes: Some(2),
        ..Limits::default()
    };
    assert!(
        extract(
            &mut a,
            0,
            &[],
            d.path(),
            &limits,
            &mut 0,
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert!(
        extract(
            &mut a,
            0,
            &[],
            d.path(),
            &Limits::default(),
            &mut 0,
            &AtomicBool::new(true)
        )
        .is_err()
    );
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
/// Ensure staged payload paths are unreadable before publication.
fn staging_path_is_inaccessible_even_before_commit() {
    use std::os::unix::fs::PermissionsExt;
    let (d, mut a) = zip("safe.txt", b"abc", false);
    let item = extract(
        &mut a,
        0,
        &[],
        d.path(),
        &Limits::default(),
        &mut 0,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(
        item.file.as_file().metadata().unwrap().permissions().mode() & 0o777,
        0
    );
    assert!(std::fs::read(item.file.path()).is_err());
}

#[test]
fn omitted_budgets_process_files_beyond_previous_size_and_ratio_caps() {
    let t = tempfile::tempdir().unwrap();
    let input = t.path().join("large");
    File::create(&input)
        .unwrap()
        .set_len(256 * 1024 * 1024 + 1)
        .unwrap();
    let item = bfsort::ingest::extraction::extract_file(
        &input,
        t.path(),
        &Limits::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(item.size, 256 * 1024 * 1024 + 1);
    drop(item);
    let (d, mut archive) = zip("small", b"abc", false);
    let mut total = 1024 * 1024 * 1024;
    let item = extract(
        &mut archive,
        0,
        &[],
        d.path(),
        &Limits::default(),
        &mut total,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(item.size, 3);
    assert_eq!(total, 1024 * 1024 * 1024 + 3);
}

#[test]
fn archive_open_accepts_more_than_old_input_and_entry_caps() {
    use std::io::{Seek, SeekFrom};
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("large.zip");
    let mut file = File::create(&path).unwrap();
    file.seek(SeekFrom::Start(1024 * 1024 * 1024 + 1)).unwrap();
    let mut writer = ZipWriter::new(file);
    writer
        .start_file("tiny", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"abc").unwrap();
    writer.finish().unwrap();
    assert!(std::fs::metadata(&path).unwrap().len() > 1024 * 1024 * 1024);
    assert_eq!(
        bfsort::output::archive::open(&path, &Limits::default())
            .unwrap()
            .len(),
        1
    );
    let path = t.path().join("many.zip");
    let mut writer = ZipWriter::new(File::create(&path).unwrap());
    for n in 0..10001 {
        writer
            .start_file(format!("{n}"), SimpleFileOptions::default())
            .unwrap();
    }
    writer.finish().unwrap();
    assert_eq!(
        bfsort::output::archive::open(&path, &Limits::default())
            .unwrap()
            .len(),
        10001
    );
    assert!(
        bfsort::output::archive::open(
            &path,
            &Limits {
                max_entries: Some(10000),
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn unzip_only_preserves_paths_without_a_repository() {
    use crate::common::{archive, run};

    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("survey.zip");
    let output = temp.path().join("extracted");
    archive(
        &input,
        &[("docs/report.pdf", b"plain text"), ("notes.txt", b"hello")],
    );
    let result = run(&[
        "ingest".as_ref(),
        "--unzip-only".as_ref(),
        input.as_os_str(),
        "--security-mode".as_ref(),
        "standard".as_ref(),
        "-o".as_ref(),
        output.as_os_str(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        std::fs::read(output.join("docs/report.pdf")).unwrap(),
        b"plain text"
    );
    assert_eq!(std::fs::read(output.join("notes.txt")).unwrap(), b"hello");
    assert!(!output.join("metadata.sqlite3").exists());
    assert!(!output.join("reports").exists());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["files"], 2);
    assert_eq!(report["expanded_bytes"], 15);
}

#[test]
fn unzip_only_never_publishes_partial_or_replaces_existing_output() {
    use crate::common::{archive, run};

    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("survey.zip");
    let output = temp.path().join("extracted");
    let args = [
        "ingest".as_ref(),
        "--unzip-only".as_ref(),
        input.as_os_str(),
        "-o".as_ref(),
        output.as_os_str(),
    ];
    archive(
        &input,
        &[("first.txt", b"safe"), ("../escape.txt", b"unsafe")],
    );
    let result = run(&args);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("traversal"));
    assert!(!output.exists());
    assert!(!temp.path().join("escape.txt").exists());

    archive(&input, &[("first.txt", b"safe")]);
    std::fs::create_dir(&output).unwrap();
    std::fs::write(output.join("first.txt"), b"existing").unwrap();
    let result = run(&args);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("output already exists"));
    assert_eq!(
        std::fs::read(output.join("first.txt")).unwrap(),
        b"existing"
    );
}
