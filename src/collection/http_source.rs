//! Discovers direct ZIP links in HTML and centralizes HTTP request restrictions.
//! URL validation, redirect checks, origin boundaries, request caps and spacing are
//! shared by page discovery and payload transfers. HTML parsing resolves relative links
//! and extracts visible titles without crawling pages or executing JavaScript.

/// Maximum redirect hops; a fixed protocol safeguard shared by acquisition commands.
const MAX_REDIRECTS: usize = 5;
/// Upper bound on cancellation latency during pacing waits.
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(25);

use crate::collection::acquisition::*;
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    io::Read,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use url::Url;

pub fn safe_url(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).map_err(|_| anyhow::anyhow!("invalid source URL"))?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none(),
        "only HTTP(S) URLs without credentials or queries are supported"
    );
    url.set_fragment(None);
    Ok(url)
}
pub fn wait_until(deadline: Instant, cancelled: &AtomicBool) -> Result<()> {
    while Instant::now() < deadline {
        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
        std::thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(CANCEL_POLL_INTERVAL),
        );
    }
    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
    Ok(())
}
struct Gate {
    count: usize,
    next: Instant,
    blocked: std::collections::BTreeSet<String>,
}
pub struct HttpSource {
    agent: ureq::Agent,
    origin: Url,
    same_origin: bool,
    interval: Duration,
    timeout: Option<Duration>,
    max_requests: Option<usize>,
    gate: Mutex<Gate>,
}
impl HttpSource {
    pub fn new(source: &SourceConfig, config: &DownloadConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            agent: ureq::Agent::config_builder()
                .max_redirects(0)
                .http_status_as_error(false)
                .timeout_global(config.timeout_seconds.map(Duration::from_secs))
                .build()
                .into(),
            origin: safe_url(&source.page)?,
            same_origin: source.same_origin,
            interval: Duration::from_millis(config.min_request_interval_ms),
            timeout: config.timeout_seconds.map(Duration::from_secs),
            max_requests: config.max_requests,
            gate: Mutex::new(Gate {
                count: 0,
                next: Instant::now(),
                blocked: Default::default(),
            }),
        })
    }
    pub fn get(
        &self,
        value: &str,
        cancelled: &AtomicBool,
    ) -> Result<(ureq::http::Response<ureq::Body>, Url)> {
        let deadline = self
            .timeout
            .map(|timeout| {
                Instant::now()
                    .checked_add(timeout)
                    .ok_or_else(|| anyhow::anyhow!("timeout too large"))
            })
            .transpose()?;
        let mut url = safe_url(value)?;
        for hop in 0..=MAX_REDIRECTS {
            ensure!(
                !self.same_origin || url.origin() == self.origin.origin(),
                "cross-origin request refused"
            );
            {
                let mut gate = self.gate.lock().unwrap();
                ensure!(
                    !gate.blocked.contains(&url.origin().ascii_serialization()),
                    "origin rate limited"
                );
                ensure!(
                    self.max_requests.is_none_or(|n| gate.count < n),
                    "request limit reached"
                );
                wait_until(
                    deadline.map_or(gate.next, |deadline| gate.next.min(deadline)),
                    cancelled,
                )?;
                ensure!(
                    deadline.is_none_or(|deadline| Instant::now() < deadline),
                    "request pacing timeout"
                );
                gate.count += 1;
                gate.next = Instant::now()
                    .checked_add(self.interval)
                    .ok_or_else(|| anyhow::anyhow!("request interval too large"))?;
            }
            let agent = self.agent.clone();
            let request_url = url.to_string();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let _ = sender.send(
                    agent
                        .get(&request_url)
                        .header("Accept-Encoding", "identity")
                        .call(),
                );
            });
            let response = receive(&receiver, cancelled, deadline)?
                .context("HTTP request failed; check connectivity and server availability")?;
            if response.status().as_u16() == 429 {
                self.gate
                    .lock()
                    .unwrap()
                    .blocked
                    .insert(url.origin().ascii_serialization());
                let retry = response
                    .headers()
                    .get("retry-after")
                    .and_then(|h| h.to_str().ok())
                    .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
                    .unwrap_or("unspecified");
                anyhow::bail!("HTTP 429; Retry-After: {retry}");
            }
            if response.status().is_redirection() {
                ensure!(hop < MAX_REDIRECTS, "redirect limit reached");
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| anyhow::anyhow!("missing redirect location"))?;
                let next = url
                    .join(location)
                    .map_err(|_| anyhow::anyhow!("invalid redirect"))?;
                ensure!(
                    url.scheme() != "https" || next.scheme() == "https",
                    "HTTPS downgrade refused"
                );
                url = safe_url(next.as_str())?;
                continue;
            }
            ensure!(
                response.status().is_success(),
                "HTTP status {}",
                response.status().as_u16()
            );
            ensure!(
                response
                    .headers()
                    .get("content-encoding")
                    .is_none_or(|v| v == "identity"),
                "encoded response refused"
            );
            return Ok((response, url));
        }
        unreachable!()
    }
}
fn original_name(encoded: &str) -> String {
    let mut bytes = Vec::with_capacity(encoded.len());
    let mut input = encoded.as_bytes().iter().copied();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let decoded = input
                .next()
                .and_then(|a| (a as char).to_digit(16))
                .zip(input.next().and_then(|b| (b as char).to_digit(16)));
            let Some((a, b)) = decoded else {
                return encoded.into();
            };
            bytes.push((a * 16 + b) as u8);
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes).unwrap_or_else(|_| encoded.into())
}

pub fn parse_links(config: &SourceConfig, final_url: &str, html: &str) -> Result<Inventory> {
    let origin = safe_url(&config.page)?;
    let page = safe_url(final_url)?;
    let document = scraper::Html::parse_document(html);
    let base_selector = scraper::Selector::parse("base[href]").unwrap();
    let base = document
        .select(&base_selector)
        .find_map(|e| {
            page.join(e.value().attr("href")?)
                .ok()
                .and_then(|u| safe_url(u.as_str()).ok())
                .filter(|u| !config.same_origin || u.origin() == origin.origin())
        })
        .unwrap_or(page);
    let selector = scraper::Selector::parse("a[href]").unwrap();
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    for element in document.select(&selector) {
        let Ok(url) = base.join(element.value().attr("href").unwrap()) else {
            continue;
        };
        let Ok(url) = safe_url(url.as_str()) else {
            continue;
        };
        if config.same_origin && url.origin() != origin.origin() {
            continue;
        }
        if !url.path().to_lowercase().ends_with(".zip") {
            continue;
        }
        let name = original_name(
            url.path_segments()
                .and_then(|mut p| p.next_back())
                .unwrap_or("download.zip"),
        );
        if !seen.insert(url.to_string()) {
            continue;
        }
        let source_id = crate::repository::metadata::digest(url.as_str().as_bytes());
        candidates.push(Candidate {
            source_id,
            url: url.to_string(),
            name,
        });
    }
    Ok(Inventory {
        version: 2,
        candidates,
    })
}
pub fn discover(
    config: &SourceConfig,
    download: &DownloadConfig,
    cancelled: &AtomicBool,
) -> Result<Inventory> {
    let _progress = crate::app::presentation::Progress::new(None, "Discovering resources");
    let started = Instant::now();
    let deadline = config
        .timeout_seconds
        .map(|seconds| {
            started
                .checked_add(Duration::from_secs(seconds))
                .ok_or_else(|| anyhow::anyhow!("timeout too large"))
        })
        .transpose()?;
    let mut page_download = download.clone();
    page_download.timeout_seconds = config.timeout_seconds;
    let http = HttpSource::new(config, &page_download)?;
    let (response, url) = http.get(&config.page, cancelled)?;
    ensure!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s
                .split(';')
                .next()
                .unwrap()
                .trim()
                .eq_ignore_ascii_case("text/html")),
        "expected HTML page"
    );
    let limit = config.max_page_size;
    let mut bytes = vec![];
    let mut reader = CancellableReader::new(response.into_body(), cancelled, deadline);
    let mut buffer = [0; 8192];
    loop {
        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        ensure!(
            limit.is_none_or(|limit| (bytes.len() as u64)
                .checked_add(n as u64)
                .is_some_and(|size| size <= limit)),
            "page size limit reached"
        );
        bytes.try_reserve(n)?;
        bytes.extend_from_slice(&buffer[..n]);
    }
    parse_links(config, url.as_str(), std::str::from_utf8(&bytes)?)
}

// Blocking network workers own no payload files. Cancellation drops their channels;
// an OS-stalled worker may outlive the operation, but cannot prevent process exit.
fn receive<T>(
    receiver: &std::sync::mpsc::Receiver<T>,
    cancelled: &AtomicBool,
    deadline: Option<Instant>,
) -> Result<T> {
    loop {
        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
        ensure!(
            deadline.is_none_or(|deadline| Instant::now() < deadline),
            "transfer timeout"
        );
        match receiver.recv_timeout(CANCEL_POLL_INTERVAL) {
            Ok(value) => return Ok(value),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => (),
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) struct CancellableReader<'a> {
    requests: std::sync::mpsc::Sender<usize>,
    results: std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
    cancelled: &'a AtomicBool,
    deadline: Option<Instant>,
}
impl<'a> CancellableReader<'a> {
    pub(crate) fn new(
        body: ureq::Body,
        cancelled: &'a AtomicBool,
        deadline: Option<Instant>,
    ) -> Self {
        let (requests, sizes) = std::sync::mpsc::channel();
        let (sender, results) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut reader = body.into_reader();
            while let Ok(size) = sizes.recv() {
                let mut bytes = vec![0; size];
                let result = reader.read(&mut bytes).map(|n| {
                    bytes.truncate(n);
                    bytes
                });
                if sender.send(result).is_err() {
                    break;
                }
            }
        });
        Self {
            requests,
            results,
            cancelled,
            deadline,
        }
    }
}
impl Read for CancellableReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let size = buffer.len().min(16 * 1024);
        self.requests.send(size).map_err(std::io::Error::other)?;
        let bytes = receive(&self.results, self.cancelled, self.deadline)
            .map_err(std::io::Error::other)??;
        buffer[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
}
