//! Command-line workflows using temporary repositories and loopback HTTP fixtures.
//!
//! Cover discovery, cached and cancelled transfers, default input modes, and
//! machine-readable output across commands.

use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(vec![]));
        let stop = Arc::new(AtomicBool::new(false));
        let (log, done) = (requests.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                            .unwrap();
                        let mut request = [0; 4096];
                        let n = stream.read(&mut request).unwrap();
                        let text = String::from_utf8_lossy(&request[..n]);
                        let path = text.split_whitespace().nth(1).unwrap().to_owned();
                        log.lock().unwrap().push(path.clone());
                        if path == "/redirect.zip" {
                            write!(stream, "HTTP/1.1 302 Found\r\nLocation: /actual.zip\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                            continue;
                        }
                        let (body, mime) = if path == "/" {
                            (
                                "<div><a href='z.zip'>Secret title</a><a href='a.zip'>Another</a><a href='z.zip#dup'>Dup</a><a href='nested/b.zip'>B</a><a href='other/a.zip'>Same filename</a><a href='redirect.zip'>Redirect</a><a href='http://['>bad</a></div>",
                                "text/html",
                            )
                        } else {
                            ("fixture payload", "application/zip")
                        };
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}
fn run(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn collect_reuses_refreshes_and_dry_run_never_fetches_payloads() {
    let server = Server::new();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("bfs.toml"),
        "[download]\nfilename = '{name}-{source_id}'",
    )
    .unwrap();
    let out = run(
        dir.path(),
        &[
            "collect",
            &server.url,
            "-o",
            "collection",
            "--dry-run",
            "--json",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!dir.path().join("collection").exists());
    assert_eq!(*server.requests.lock().unwrap(), ["/"]);
    let out = run(
        dir.path(),
        &[
            "collect",
            &server.url,
            "-o",
            "collection",
            "-j",
            "1",
            "--json",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["downloaded"], 5);
    let inventory = std::fs::read(dir.path().join("collection/inventory.json")).unwrap();
    assert!(!dir.path().join("collection/inventory.jsonl").exists());
    std::fs::rename(
        dir.path().join("collection/inventory.json"),
        dir.path().join("collection/inventory.jsonl"),
    )
    .unwrap();
    let n = server.requests.lock().unwrap().len();
    let download = run(dir.path(), &["download", "--dry-run", "--json"]);
    assert!(!download.status.success());
    assert_eq!(server.requests.lock().unwrap().len(), n);
    std::fs::copy(
        dir.path().join("collection/inventory.jsonl"),
        dir.path().join("collection/inventory.json"),
    )
    .unwrap();
    let out = run(
        dir.path(),
        &["collect", "-o", "collection", "--dry-run", "--json"],
    );
    assert!(out.status.success());
    assert_eq!(server.requests.lock().unwrap().len(), n);
    let download = run(dir.path(), &["download", "--dry-run", "--json"]);
    assert!(
        download.status.success(),
        "{}",
        String::from_utf8_lossy(&download.stderr)
    );
    assert_eq!(server.requests.lock().unwrap().len(), n);
    let out = run(
        dir.path(),
        &[
            "collect",
            &server.url,
            "-o",
            "collection",
            "--refresh",
            "--dry-run",
            "--json",
        ],
    );
    assert!(out.status.success());
    assert_eq!(server.requests.lock().unwrap().len(), n + 1);
    assert_eq!(
        std::fs::read(dir.path().join("collection/inventory.jsonl")).unwrap(),
        inventory
    );
}
#[test]
fn discovery_public_listing_has_only_filenames_in_dom_order() {
    let server = Server::new();
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), &["discover", &server.url]);
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "z.zip\na.zip\nb.zip\na.zip\nredirect.zip\n"
    );
    let out = run(
        dir.path(),
        &["--color", "always", "discover", &server.url, "--json"],
    );
    assert!(out.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap(),
        serde_json::json!({"files": ["z.zip", "a.zip", "b.zip", "a.zip", "redirect.zip"]})
    );
    assert!(!out.stdout.contains(&27));
    assert!(!out.stderr.contains(&27));
}
#[test]
fn ingest_defaults_to_files_and_extract_is_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let file = std::fs::File::create(dir.path().join("input.zip")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("hello.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"hello").unwrap();
    zip.finish().unwrap();
    for (extra, output, expected) in [
        (vec![], "files", "input.zip"),
        (vec!["--extract"], "archives", "hello.txt"),
    ] {
        let mut args = vec!["ingest", "input.zip", "-o", output, "--json"];
        args.extend(extra);
        let out = run(dir.path(), &args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let records = bfsort::repository::metadata::load(&dir.path().join(output)).unwrap();
        let value = serde_json::to_value(&records[0]).unwrap();
        assert_eq!(value["original_name"], expected);
    }
}
#[test]
fn color_and_quiet_never_pollute_json_or_piped_auto() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        vec!["config", "validate"],
        vec!["--color", "never", "config", "validate"],
        vec!["--color", "always", "--no-color", "config", "validate"],
        vec!["--json", "--color", "always", "config", "validate"],
    ] {
        let out = run(dir.path(), &args);
        assert!(out.status.success());
        assert!(!out.stdout.contains(&27));
        assert!(!out.stderr.contains(&27));
    }
    assert!(
        run(dir.path(), &["--color", "always", "config", "validate"])
            .stdout
            .contains(&27)
    );
    assert!(
        run(dir.path(), &["--quiet", "config", "validate"])
            .stdout
            .is_empty()
    );
}

#[test]
fn obsolete_acquisition_state_is_rejected_without_deleting_it() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("collection")).unwrap();
    let path = dir.path().join("collection/inventory.json");
    bfsort::collection::acquisition::save_json(
        &path,
        &serde_json::json!({"version":1,"candidates":[]}),
    )
    .unwrap();
    let obsolete = std::fs::read_to_string(&path).unwrap();
    let out = run(dir.path(), &["download", "--dry-run"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("re-discover"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), obsolete);
    bfsort::collection::acquisition::private_tree(&dir.path().join("collection/downloads/control"))
        .unwrap();
    bfsort::collection::acquisition::save_json(
        &dir.path().join("collection/downloads/control/old.json"),
        &serde_json::json!({"version":1}),
    )
    .unwrap();
    let out = run(dir.path(), &["ingest"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("re-download"));
}

#[test]
fn config_precedence_and_errors_are_actionable_without_secrets() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bfs.toml"), "workers = 0").unwrap();
    std::fs::write(
        dir.path().join("explicit.toml"),
        "workers = 1\noutput = 'from-config'",
    )
    .unwrap();
    std::fs::write(dir.path().join("file.txt"), "hello").unwrap();
    std::fs::create_dir(dir.path().join("incoming")).unwrap();
    std::fs::write(dir.path().join("incoming/default.txt"), "default input").unwrap();
    let defaults = run(
        dir.path(),
        &["ingest", "-c", "explicit.toml", "--dry-run", "--json"],
    );
    assert!(
        defaults.status.success(),
        "{}",
        String::from_utf8_lossy(&defaults.stderr)
    );

    let out = run(
        dir.path(),
        &[
            "ingest",
            "file.txt",
            "-c",
            "explicit.toml",
            "-o",
            "from-cli",
            "-j",
            "2",
            "--verbose",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.path().join("from-cli").is_dir());
    assert!(!dir.path().join("from-config").exists());
    assert!(String::from_utf8_lossy(&out.stderr).contains("explicit.toml"));
    std::fs::write(
        dir.path().join("secret.toml"),
        "[source]\npage = 'https://user:PRIVATE_PASSWORD@example.org/\n",
    )
    .unwrap();
    let out = run(
        dir.path(),
        &["config", "validate", "-c", "secret.toml", "--verbose"],
    );
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("PRIVATE_PASSWORD"));
}

#[cfg(unix)]
#[test]
fn sealed_local_inputs_require_explicit_unlock() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sealed.zip");
    std::fs::write(&path, "payload").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    let out = run(dir.path(), &["ingest", "sealed.zip", "--quiet"]);
    assert!(!out.status.success());
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(
        error.contains("sealed") && error.contains("unlock"),
        "{error}"
    );
    assert!(!dir.path().join("organized").exists());
}

#[cfg(unix)]
#[test]
fn ctrl_c_stops_parallel_transfers_without_publishing_partials() {
    let server = Server::new();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("collection.toml"), format!("[source]\npage = {:?}\n[download]\nmax_speed = '1 B/s'\nfilename = '{{source_id}}'\nconcurrency = 2\ntimeout_seconds = 2\n", server.url)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .current_dir(dir.path())
        .args(["collect", "-c", "collection.toml", "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    while server.requests.lock().unwrap().len() < 2 && started.elapsed().as_secs() < 2 {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        if deadline.elapsed().as_secs() > 5 {
            child.kill().unwrap();
            panic!("cancellation did not finish");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["downloaded"], 0);
    assert!(String::from_utf8_lossy(&out.stderr).contains("interrupted"));
    assert!(!out.stdout.contains(&27));
    assert!(!out.stderr.contains(&27));
    let payloads = dir.path().join("collection/downloads/payloads");
    assert!(std::fs::read_dir(payloads).unwrap().next().is_none());
}
