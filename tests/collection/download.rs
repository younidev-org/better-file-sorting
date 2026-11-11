// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Integration checks for download tests.
//! Exercises public BFS behavior with disposable fixtures; failures should identify
//! contract regressions without changing user repositories.

use bfsort::{collection::acquisition::*, collection::download};
#[test]
fn dry_run_never_creates_staging() {
    let temp = tempfile::tempdir().unwrap();
    let config = DownloadConfig {
        staging_dir: temp.path().join("absent"),
        ..Default::default()
    };
    let inventory = Inventory {
        version: 2,
        candidates: vec![],
    };
    assert_eq!(
        download::preview(&config, &inventory).unwrap().downloaded,
        0
    );
    assert!(!config.staging_dir.exists());
}

fn transfer(
    body: &'static [u8],
    limit: &str,
) -> (tempfile::TempDir, DownloadConfig, DownloadReport) {
    transfer_with_speed(body, limit, None)
}
fn transfer_with_speed(
    body: &'static [u8],
    limit: &str,
    speed: Option<String>,
) -> (tempfile::TempDir, DownloadConfig, DownloadReport) {
    transfer_response(body, limit, speed, true)
}
fn transfer_response(
    body: &'static [u8],
    limit: &str,
    speed: Option<String>,
    known_length: bool,
) -> (tempfile::TempDir, DownloadConfig, DownloadReport) {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::atomic::AtomicBool,
    };
    let root = tempfile::tempdir().unwrap();
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/a.zip", server.local_addr().unwrap());
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        if known_length {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
        } else {
            write!(stream, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n").unwrap();
        }
        let _ = stream.write_all(body);
    });
    let candidate = Candidate {
        source_id: bfsort::repository::metadata::digest(url.as_bytes()),
        url: url.clone(),
        name: "a.zip".into(),
    };
    let config = DownloadConfig {
        staging_dir: root.path().join("downloads"),
        max_file_size: Some(bfsort::collection::acquisition::parse_bytes(limit).unwrap()),
        max_speed: speed,
        timeout_seconds: Some(1),
        ..Default::default()
    };
    let report = download::run(
        &config,
        &SourceConfig {
            page: url,
            ..Default::default()
        },
        &Inventory {
            version: 2,
            candidates: vec![candidate],
        },
        &AtomicBool::new(false),
    )
    .unwrap();
    thread.join().unwrap();
    (root, config, report)
}
#[test]
fn downloaded_payload_is_sealed_and_receipted() {
    use std::os::unix::fs::PermissionsExt;
    let (_root, config, report) = transfer(b"fixture", "1 KB");
    assert_eq!(report.downloaded, 1, "{:?}", report.errors);
    assert_eq!(report.bytes, 7);
    let path = config
        .staging_dir
        .join(download::payload_path(&config, &report.candidates[0]));
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0
    );
}
#[test]
fn over_limit_payload_is_not_published() {
    let (_root, config, report) = transfer(b"too large", "3 B");
    assert_eq!(report.failed, 1);
    assert!(
        !config
            .staging_dir
            .join(download::payload_path(&config, &report.candidates[0]))
            .exists()
    );
}

#[test]
fn sealed_receipt_requires_explicit_unlock_then_verifies_hash() {
    use std::os::unix::fs::PermissionsExt;
    let (_root, config, report) = transfer(b"fixture", "1 KB");
    assert!(
        bfsort::collection::acquisition::completed_inputs(&config)
            .unwrap_err()
            .to_string()
            .contains("unlock")
    );
    let path = config
        .staging_dir
        .join(download::payload_path(&config, &report.candidates[0]));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        bfsort::collection::acquisition::completed_inputs(&config)
            .unwrap()
            .len(),
        1
    );
    std::fs::write(&path, b"changed").unwrap();
    assert!(bfsort::collection::acquisition::completed_inputs(&config).is_err());
}

#[test]
fn downloaded_zip_flows_through_existing_ingest() {
    use std::{io::Write, os::unix::fs::PermissionsExt, sync::atomic::AtomicBool};
    let mut bytes = std::io::Cursor::new(vec![]);
    {
        let mut zip = zip::ZipWriter::new(&mut bytes);
        zip.start_file("hello.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();
    }
    let (root, config, report) = transfer(Box::leak(bytes.into_inner().into_boxed_slice()), "1 MB");
    let payload = config
        .staging_dir
        .join(download::payload_path(&config, &report.candidates[0]));
    std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config_path = root.path().join("collection.toml");
    std::fs::write(
        &config_path,
        format!(
            "output = '{}'\nzip = true\n[download]\nstaging_dir = '{}'\n",
            root.path().join("sorted.zip").display(),
            config.staging_dir.display()
        ),
    )
    .unwrap();
    use clap::Parser;
    let bfsort::app::cli::Command::Ingest(args) = bfsort::app::cli::Cli::parse_from([
        "bfs",
        "ingest",
        "--config",
        config_path.to_str().unwrap(),
    ])
    .command
    else {
        panic!()
    };
    let ingest = bfsort::app::config::Config::for_ingest(&args).unwrap();
    let preview = bfsort::ingest::pipeline::preview(&ingest, &AtomicBool::new(false)).unwrap();
    assert_eq!(preview.plan.len(), 1);
    let result = bfsort::ingest::pipeline::ingest(&ingest, &AtomicBool::new(false)).unwrap();
    assert_eq!(result.accepted, 1);
    assert_eq!(result.failures, 0);
    assert!(root.path().join("sorted.zip").is_file());

    let mut resume = ingest;
    resume.zip = false;
    resume.resume = true;
    resume.input_mode = bfsort::app::config::InputMode::Archives;
    resume.output = root.path().join("repository");
    let cancelled = AtomicBool::new(false);
    assert_eq!(
        bfsort::ingest::pipeline::ingest(&resume, &cancelled)
            .unwrap()
            .accepted,
        1
    );
    let unchanged = bfsort::ingest::pipeline::ingest(&resume, &cancelled).unwrap();
    assert_eq!(unchanged.reused_occurrences, 1);
    let original_size = std::fs::metadata(&payload).unwrap().len();
    crate::common::archive(&payload, &[("hello.txt", b"hello again")]);
    assert_eq!(std::fs::metadata(&payload).unwrap().len(), original_size);
    let result = bfsort::ingest::pipeline::ingest(&resume, &cancelled).unwrap();
    assert_eq!(result.accepted, 0);
    assert_eq!(result.reused_occurrences, 0);
    assert!(
        result
            .first_failure
            .unwrap()
            .error
            .contains("download hash changed")
    );
}

#[test]
fn unicode_names_fit_filesystem_component_limits() {
    let config = DownloadConfig::default();
    let candidate = Candidate {
        source_id: "a".repeat(64),
        url: "http://localhost/a.zip".into(),
        name: format!("{}.zip", "界".repeat(100)),
    };
    let path = download::payload_path(&config, &candidate);
    assert!(path.components().all(|c| c.as_os_str().len() <= 255));
}

#[test]
fn final_chunk_pacing_cannot_publish_after_timeout() {
    let (_root, config, report) = transfer_with_speed(b"fixture", "1 KB", Some("1 B/s".into()));
    assert_eq!(report.failed, 1);
    assert!(
        !config
            .staging_dir
            .join(download::payload_path(&config, &report.candidates[0]))
            .exists()
    );
}

#[test]
fn completed_source_is_cached() {
    use std::sync::atomic::AtomicBool;
    let (_root, config, report) = transfer(b"fixture", "1 KB");
    let candidate = report.candidates[0].clone();
    let source = SourceConfig {
        page: candidate.url.clone(),
        ..Default::default()
    };
    let result = download::run(
        &config,
        &source,
        &Inventory {
            version: 2,
            candidates: vec![candidate],
        },
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(result.cached, 1);
    assert_eq!(result.downloaded, 0);
}

#[test]
fn filename_templates_keep_extension_once_and_reject_invalid_templates() {
    let candidate = Candidate {
        source_id: "a".repeat(64),
        url: "http://localhost/sample.tar.gz".into(),
        name: "sample.tar.gz".into(),
    };
    for (template, expected) in [
        ("{original_name}", "sample.tar.gz".to_string()),
        (
            "{name}-{source_id}",
            format!("sample.tar-{}.gz", candidate.source_id),
        ),
        ("{source_id}", format!("{}.gz", candidate.source_id)),
    ] {
        let config = DownloadConfig {
            filename: template.into(),
            directory: "daily".into(),
            ..Default::default()
        };
        config.validate().unwrap();
        assert_eq!(
            download::payload_path(&config, &candidate),
            std::path::Path::new("payloads/daily").join(expected)
        );
        assert_eq!(candidate.name, "sample.tar.gz");
    }
    for filename in ["{name}", "{original_name}.zip", "../x", ""] {
        assert!(
            DownloadConfig {
                filename: filename.into(),
                ..Default::default()
            }
            .validate()
            .unwrap_err()
            .to_string()
            .contains("download.filename")
        );
    }
}

#[test]
fn unsafe_names_are_single_portable_components() {
    let config = DownloadConfig::default();
    for name in [
        "../../evil.zip",
        "CON.zip",
        "NUL",
        "back\\slash.zip",
        "x\u{202e}gpj.zip",
        "bad\nname.zip",
        ".",
        "x. ",
    ] {
        let candidate = Candidate {
            source_id: "a".repeat(64),
            url: String::new(),
            name: name.into(),
        };
        let path = download::payload_path(&config, &candidate);
        assert_eq!(path.components().count(), 2, "{path:?}");
        let filename = path.file_name().unwrap().to_str().unwrap();
        assert!(!filename.ends_with(['.', ' ']));
        assert!(!filename.contains(['\\', '\n', '\u{202e}']));
        assert_ne!(filename, "CON.zip");
        assert_ne!(filename, "NUL");
    }
}

#[test]
fn duplicate_output_names_fail_before_staging_is_created() {
    let root = tempfile::tempdir().unwrap();
    let config = DownloadConfig {
        staging_dir: root.path().join("absent"),
        ..Default::default()
    };
    let inventory = Inventory {
        version: 2,
        candidates: ["http://localhost/a/same.zip", "http://localhost/b/same.zip"]
            .into_iter()
            .map(|url| Candidate {
                source_id: bfsort::repository::metadata::digest(url.as_bytes()),
                url: url.into(),
                name: "same.zip".into(),
            })
            .collect(),
    };
    assert!(
        download::run(
            &config,
            &SourceConfig {
                page: "http://localhost/".into(),
                ..Default::default()
            },
            &inventory,
            &std::sync::atomic::AtomicBool::new(false)
        )
        .unwrap_err()
        .to_string()
        .contains("collision")
    );
    assert!(!config.staging_dir.exists());
    let config = DownloadConfig {
        filename: "{name}-{source_id}".into(),
        ..config
    };
    assert!(download::preview(&config, &inventory).is_ok());
}

#[test]
fn unknown_length_transfers_count_actual_bytes() {
    let (_root, _config, report) = transfer_response(b"unknown-size fixture", "1 KB", None, false);
    assert_eq!(report.downloaded, 1, "{:?}", report.errors);
    assert_eq!(report.bytes, 20);
    assert_eq!(report.failed, 0);
}

#[test]
fn unlimited_transfer_cancels_while_response_body_stalls() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };
    let temp = tempfile::tempdir().unwrap();
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/stall.zip", server.local_addr().unwrap());
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    let (release, wait) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n")
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        signal.store(true, Ordering::Relaxed);
        let _ = wait.recv_timeout(Duration::from_secs(3));
    });
    let config = DownloadConfig {
        staging_dir: temp.path().join("download"),
        ..Default::default()
    };
    let candidate = Candidate {
        source_id: bfsort::repository::metadata::digest(url.as_bytes()),
        url: url.clone(),
        name: "stall.zip".into(),
    };
    let started = Instant::now();
    let report = download::run(
        &config,
        &SourceConfig {
            page: url,
            ..Default::default()
        },
        &Inventory {
            version: 2,
            candidates: vec![candidate],
        },
        &cancelled,
    )
    .unwrap();
    assert_eq!(report.failed, 1);
    assert!(
        report.errors[0].contains("interrupted"),
        "{:?}",
        report.errors
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    release.send(()).unwrap();
    thread.join().unwrap();
    assert_eq!(
        std::fs::read_dir(config.staging_dir.join("payloads"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn stalled_body_does_not_hold_the_download_budget_lock() {
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };

    let root = tempfile::tempdir().unwrap();
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", server.local_addr().unwrap());
    let config = DownloadConfig {
        staging_dir: root.path().join("downloads"),
        concurrency: 2,
        timeout_seconds: Some(5),
        max_total_size: Some(12),
        max_staging_size: Some(12),
        ..Default::default()
    };
    let candidates: Vec<_> = ["slow.zip", "fast.zip"]
        .into_iter()
        .map(|name| {
            let url = format!("{base}/{name}");
            Candidate {
                source_id: bfsort::repository::metadata::digest(url.as_bytes()),
                url,
                name: name.into(),
            }
        })
        .collect();
    let receipt = config
        .staging_dir
        .join("control")
        .join(format!("{}.json", candidates[1].source_id));

    let server = std::thread::spawn(move || {
        let mut slow = None;
        let mut fast = None;
        for _ in 0..2 {
            let (stream, _) = server.accept().unwrap();
            let mut stream = BufReader::new(stream);
            let mut request = String::new();
            stream.read_line(&mut request).unwrap();
            let mut header = String::new();
            loop {
                header.clear();
                assert_ne!(stream.read_line(&mut header).unwrap(), 0);
                if header == "\r\n" {
                    break;
                }
            }
            let stream = stream.into_inner();
            if request.starts_with("GET /slow.zip ") {
                slow = Some(stream);
            } else {
                assert!(request.starts_with("GET /fast.zip "));
                fast = Some(stream);
            }
        }
        let mut slow = slow.unwrap();
        slow.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n")
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        fast.unwrap()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nfast")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !receipt.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let completed_before_release = receipt.is_file();
        slow.write_all(b"slowbody").unwrap();
        completed_before_release
    });
    let report = download::run(
        &config,
        &SourceConfig {
            page: base,
            ..Default::default()
        },
        &Inventory {
            version: 2,
            candidates,
        },
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(
        server.join().unwrap(),
        "fast transfer waited for the stalled body"
    );
    assert_eq!(report.downloaded, 2, "{:?}", report.errors);
    assert_eq!(report.bytes, 12);
}
