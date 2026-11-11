// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Exercises classification, rule parsing, archive names, and report serialization with bounded fuzz inputs.

#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = bfsort::organization::rules::Rules::parse(text);
        let _ = bfsort::ingest::extraction::validate_name(text);
        let _ = bfsort::organization::rules::sanitize(text);
    }
    let _ = bfsort::detection::classifier::classify(data);
    let detection = bfsort::detection::classifier::detect(data);
    let _ = bfsort::detection::classifier::detect_reader(data, &mut std::io::Cursor::new(data));
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = bfsort::detection::mismatch::extension(text);
        let _ = bfsort::detection::mismatch::normalize_extension(text);
        let _ = bfsort::detection::mismatch::evaluate(text, &detection);
        if let Ok(record) = serde_json::from_str::<bfsort::repository::metadata::Occurrence>(text) {
            if record.validate().is_ok() {
                let records = [record];
                let report = bfsort::output::report::mismatches(
                    &records,
                    &[],
                    bfsort::detection::classifier::Confidence::Unknown,
                    true,
                );
                for format in [
                    bfsort::output::report::ReportFormat::Json,
                    bfsort::output::report::ReportFormat::Csv,
                    bfsort::output::report::ReportFormat::Table,
                ] {
                    let _ = report.write(std::io::sink(), format);
                }
            }
        }
    }
    if let Ok(archive) = zip::ZipArchive::new(std::io::Cursor::new(data)) {
        for index in 0..archive.len().min(1000) {
            if let Ok(entry) = archive.by_index_data(index) {
                let _ = entry.name();
            }
        }
    }
});
