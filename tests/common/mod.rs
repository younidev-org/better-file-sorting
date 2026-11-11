// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Shared integration fixtures for ZIP inputs, CLI subprocesses, and catalog queries.

#![allow(dead_code)]
use std::{
    fs::File,
    io::Write,
    path::Path,
    process::{Command, Output},
};
/// Create a synthetic ZIP archive for integration tests.
pub fn archive(path: &Path, entries: &[(&str, &[u8])]) {
    let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
    for (name, bytes) in entries {
        zip.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
}
/// Run the compiled CLI with native argument values.
pub fn run(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .arg("--json")
        .args(args)
        .args(
            if args.first().is_some_and(|a| *a == "ingest")
                && !args.iter().any(|a| {
                    matches!(
                        a.to_str(),
                        Some("--input-mode" | "--config" | "-c" | "--extract" | "--unzip-only")
                    )
                })
            {
                vec![std::ffi::OsStr::new("--extract")]
            } else {
                vec![]
            },
        )
        .output()
        .unwrap()
}
/// Run ingestion with a selected worker count.
pub fn ingest(input: &Path, output: &Path, workers: &str) -> Output {
    run(&[
        "ingest".as_ref(),
        input.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
        "--workers".as_ref(),
        workers.as_ref(),
    ])
}
/// Read occurrence records from a test repository's catalog.
pub fn manifest(root: &Path) -> Vec<serde_json::Value> {
    bfsort::repository::metadata::load_all(root)
        .unwrap()
        .into_iter()
        .map(|r| serde_json::to_value(r).unwrap())
        .collect()
}
