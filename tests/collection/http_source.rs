//! HTTP discovery, URL handling, redirect budgets, rate limits, and inventory ordering.

use bfsort::{collection::acquisition::SourceConfig, collection::http_source::parse_links};
#[test]
fn links_are_resolved_and_first_url_keeps_dom_order() {
    let config = SourceConfig {
        page: "http://localhost/index".into(),
        ..Default::default()
    };
    let result = parse_links(&config, &config.page, r#"<a href='/a.ZIP#one'>Linux &amp; tools</a><a href='/a.ZIP#two'>Duplicate</a><a href='other.txt'>No</a><a href='http://elsewhere/b.zip'>Other</a>"#).unwrap();
    assert_eq!(result.candidates.len(), 1);
    assert_eq!(result.candidates[0].name, "a.ZIP");
    assert_eq!(result.candidates[0].url, "http://localhost/a.ZIP");
}

#[test]
fn discovery_reads_local_http_page_and_limits_redirect_requests() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::atomic::AtomicBool,
    };
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let page = format!("http://{}/", server.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut request = [0; 2048];
        assert!(stream.read(&mut request).unwrap() > 0);
        let body = "<a href='/a.zip'>Fixture</a>";
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
    });
    let source = SourceConfig {
        page,
        ..Default::default()
    };
    let result = bfsort::collection::http_source::discover(
        &source,
        &Default::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(result.candidates[0].name, "a.zip");
    handle.join().unwrap();
}

#[test]
fn redirect_hops_consume_request_budget() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::atomic::AtomicBool,
    };
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let page = format!("http://{}/", server.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut request = [0; 2048];
        assert!(stream.read(&mut request).unwrap() > 0);
        write!(stream,"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    });
    let config = bfsort::collection::acquisition::DownloadConfig {
        max_requests: Some(1),
        ..Default::default()
    };
    let http = bfsort::collection::http_source::HttpSource::new(
        &SourceConfig {
            page: page.clone(),
            ..Default::default()
        },
        &config,
    )
    .unwrap();
    assert!(
        http.get(&page, &AtomicBool::new(false))
            .unwrap_err()
            .to_string()
            .contains("request limit")
    );
    handle.join().unwrap();
}

#[test]
fn rate_limited_origin_is_not_requested_again() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::atomic::AtomicBool,
    };
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let page = format!("http://{}/", server.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut request = [0; 2048];
        assert!(stream.read(&mut request).unwrap() > 0);
        write!(stream,"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    });
    let http = bfsort::collection::http_source::HttpSource::new(
        &SourceConfig {
            page: page.clone(),
            ..Default::default()
        },
        &Default::default(),
    )
    .unwrap();
    let flag = AtomicBool::new(false);
    assert!(
        http.get(&page, &flag)
            .unwrap_err()
            .to_string()
            .contains("Retry-After: 60")
    );
    handle.join().unwrap();
    assert!(
        http.get(&page, &flag)
            .unwrap_err()
            .to_string()
            .contains("origin rate limited")
    );
}

#[test]
fn discover_url_cli_writes_default_inventory_without_config() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        process::Command,
    };
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", server.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        let body = "<a href='/fixture.zip'>Fixture ZIP</a>";
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
    });
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .args(["discover", &url])
        .current_dir(temp.path())
        .output()
        .unwrap();
    worker.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let inventory = bfsort::collection::acquisition::load_inventory(
        &temp.path().join("collection/inventory.json"),
    )
    .unwrap();
    assert_eq!(inventory.candidates.len(), 1);
    assert_eq!(inventory.candidates[0].name, "fixture.zip");
    assert!(!temp.path().join("collection/inventory.jsonl").exists());
}

#[test]
fn default_workflow_needs_no_config_file() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        os::unix::fs::PermissionsExt,
        process::Command,
    };
    let mut archive = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut archive);
        writer
            .start_file("hello.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"hello").unwrap();
        writer.finish().unwrap();
    }
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", server.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        for (body, content_type) in [
            (b"<a href='/fixture.zip'>Fixture</a>".to_vec(), "text/html"),
            (archive.into_inner(), "application/zip"),
        ] {
            let (mut stream, _) = server.accept().unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let result = Command::new(env!("CARGO_BIN_EXE_bfsort"))
            .args(args)
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        result
    };
    run(&["discover", &url]);
    run(&["download", "--dry-run"]);
    run(&["download"]);
    worker.join().unwrap();
    let config = bfsort::collection::acquisition::DownloadConfig {
        staging_dir: temp.path().join("collection/downloads"),
        ..Default::default()
    };
    let control = config.staging_dir.join("control");
    let receipt_path = std::fs::read_dir(control)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .unwrap();
    let receipt: bfsort::collection::acquisition::DownloadReceipt =
        bfsort::collection::acquisition::load_json(&receipt_path).unwrap();
    std::fs::set_permissions(
        config.staging_dir.join(receipt.path),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    run(&["ingest", "--dry-run"]);
    run(&["ingest"]);
    assert!(temp.path().join("organized/security.json").is_file());
    run(&["stats"]);
    run(&["reorganize", "--dry-run"]);
}

#[test]
fn discovery_keeps_dom_order_and_download_priority_is_separate() {
    use bfsort::collection::acquisition::*;
    let source = SourceConfig {
        page: "http://localhost/".into(),
        ..Default::default()
    };
    let inventory = parse_links(&source, &source.page, r#"<a href='z.zip'>Title</a><div><a href='a.zip'>Nested</a></div><a href='z.zip#again'>Duplicate</a><a href='other/a.zip'>Same name</a><a href='http://['>Bad</a>"#).unwrap();
    let names = || {
        inventory
            .candidates
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(names(), ["z.zip", "a.zip", "a.zip"]);
    assert_eq!(
        select_candidates(&inventory, &DownloadConfig::default()).unwrap()[0].name,
        "z.zip"
    );
    let config = DownloadConfig {
        order_by: OrderBy::Name,
        ..Default::default()
    };
    assert_eq!(
        select_candidates(&inventory, &config).unwrap()[0].name,
        "a.zip"
    );
    assert_eq!(names(), ["z.zip", "a.zip", "a.zip"]);
    let value = serde_json::to_value(&inventory).unwrap();
    assert!(value["candidates"][0].get("title").is_none());
    assert!(value["candidates"][0].get("discovered_at").is_none());
}

#[test]
fn discovery_decodes_original_filename_without_trusting_link_title() {
    let source = SourceConfig {
        page: "http://localhost/".into(),
        ..Default::default()
    };
    let inventory = parse_links(
        &source,
        &source.page,
        "<a href='hello%20world%2B.zip'>../../wrong.zip</a>",
    )
    .unwrap();
    assert_eq!(inventory.candidates[0].name, "hello world+.zip");
    assert_eq!(
        inventory.candidates[0].url,
        "http://localhost/hello%20world%2B.zip"
    );
}
