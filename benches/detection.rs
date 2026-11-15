//! Measures end-to-end Linux file(1) classification on a small MIME corpus.

use bfsort::detection::classifier::detect_file;
use std::{hint::black_box, io::Write, time::Instant};

fn main() -> anyhow::Result<()> {
    let fixtures: &[(&str, &[u8])] = &[
        ("application/pdf", b"%PDF-1.7\nfixture\n"),
        ("text/plain", b"ordinary benign prose"),
        (
            "image/svg+xml",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>",
        ),
        ("application/octet-stream", b"\x00\x01\x02\xff"),
    ];
    let mut files = Vec::new();
    for (mime, bytes) in fixtures {
        let mut file = tempfile::tempfile()?;
        file.write_all(bytes)?;
        assert_eq!(detect_file(&mut file)?.mime_type.as_deref(), Some(*mime));
        files.push(file);
    }
    let iterations = 100;
    let start = Instant::now();
    for _ in 0..iterations {
        for file in &mut files {
            black_box(detect_file(file)?);
        }
    }
    let seconds = start.elapsed().as_secs_f64();
    println!(
        "{}",
        serde_json::json!({
            "detector": "linux-file",
            "files_per_second": (iterations * files.len()) as f64 / seconds,
            "seconds": seconds
        })
    );
    Ok(())
}
