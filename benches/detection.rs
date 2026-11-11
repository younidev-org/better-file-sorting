//! Benchmarks content detection and extension matching on a small labelled corpus.
//!
//! The synthetic fixtures measure detector throughput and exercise expected
//! classifications.

use bfsort::{
    detection::classifier::{self, Confidence},
    detection::mismatch::{self, Status},
};
use std::{
    hint::black_box,
    io::{Cursor, Write},
    time::Instant,
};
fn main() -> anyhow::Result<()> {
    let fixtures: &[(&str, &[u8])] = &[
        ("pdf", b"%PDF-1.7\nfixture\n"),
        ("json", b"{\"fixture\": true}"),
        ("text", b"ordinary benign prose"),
        ("python", b"#!/usr/bin/env python3\nprint('fixture')\n"),
        ("png", b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"),
        ("unknown", b"\x00\x01\x02\xff"),
    ];
    for (expected, bytes) in fixtures {
        assert_eq!(
            classifier::detect(bytes).detected_format.as_str(),
            *expected
        );
    }
    let iterations = 100_000;
    for enhanced in [false, true] {
        let start = Instant::now();
        for _ in 0..iterations {
            for (_, bytes) in fixtures {
                if enhanced {
                    black_box(classifier::detect(black_box(bytes)));
                } else {
                    black_box(classifier::classify(black_box(bytes)));
                }
            }
        }
        let seconds = start.elapsed().as_secs_f64();
        println!(
            "{}",
            serde_json::json!({"detector": if enhanced {"enhanced_prefix"} else {"legacy_prefix"}, "files_per_second": (iterations * fixtures.len()) as f64 / seconds, "seconds": seconds, "requested_identifiers_matched": fixtures.iter().filter(|(expected, bytes)| { if enhanced { classifier::detect(bytes).detected_format.as_str() == *expected } else { classifier::classify(bytes) == *expected } }).count(), "labelled_total": fixtures.len()})
        );
    }
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for name in ["[Content_Types].xml", "word/document.xml"] {
        zip.start_file(name, zip::write::SimpleFileOptions::default())?;
        zip.write_all(b"benign fixture")?;
    }
    let bytes = zip.finish()?.into_inner();
    let mut reader = Cursor::new(&bytes);
    let prefix = &bytes[..bytes.len().min(8192)];
    assert_eq!(
        classifier::detect_reader(prefix, &mut reader)
            .detected_format
            .as_str(),
        "docx"
    );
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(classifier::detect_reader(black_box(prefix), &mut reader));
    }
    println!(
        "{}",
        serde_json::json!({"detector": "zip_directory", "files_per_second": iterations as f64 / start.elapsed().as_secs_f64(), "seconds": start.elapsed().as_secs_f64()})
    );
    let pdf = classifier::detect(b"%PDF-1.7\n");
    let text = classifier::detect(b"ordinary prose");
    let mut correct = 0;
    for (name, detection, status) in [
        ("a.pdf", &pdf, Status::Match),
        ("a.exe", &pdf, Status::Mismatch),
        ("a.js", &text, Status::Ambiguous),
        ("sample", &pdf, Status::MissingExtension),
        ("a.bin", &pdf, Status::Compatible),
    ] {
        assert_eq!(mismatch::evaluate(name, detection).status, status);
        correct += 1;
    }
    assert_eq!(pdf.confidence, Confidence::High);
    println!(
        "{}",
        serde_json::json!({"mismatch_decisions_correct": correct, "mismatch_decisions_total": 5, "definitive_mismatches": 1, "false_mismatches": 0, "detection_struct_bytes": std::mem::size_of::<classifier::Detection>()})
    );
    Ok(())
}
