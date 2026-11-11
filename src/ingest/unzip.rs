// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Extract ZIPs into a plain directory using the ingest path, integrity, and permission checks.

use crate::{
    app::{
        config::{Config, InputMode},
        presentation::{Progress, bytes},
    },
    collection::acquisition::private_tree,
    ingest::{discovery, extraction, pipeline},
    output::archive,
    repository::security,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    cell::Cell,
    fs::File,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

/// Totals for a published extraction-only output.
#[derive(Default, Serialize)]
pub struct Report {
    pub archives: usize,
    pub files: usize,
    pub expanded_bytes: u64,
}

/// Extract all entries into a new directory, preserving archive paths and configured permissions.
///
/// Multiple ZIPs get separate directories named after their archive stems. Publication
/// waits for every archive to pass validation, so failures leave the destination absent.
pub fn run(config: &Config, cancelled: &AtomicBool) -> Result<Report> {
    config.validate()?;
    ensure!(
        config.input_mode == InputMode::Archives,
        "unzip requires archive inputs"
    );
    let output = &config.output;
    discovery::check_path(output)?;
    ensure!(
        !output.try_exists()?,
        "unzip output already exists; choose a fresh directory"
    );
    let passwords = security::passwords(config.password_file.as_deref())?;
    let archives = discovery::for_ingest(config)?;
    ensure!(!archives.is_empty(), "no matching ZIP archives found");
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        private_tree(parent)?;
    }
    let staging = security::private_tempdir(parent, ".bfs-unzip-")?;
    let progress = Progress::new(Some(archives.len() as u64), "Extracting ZIPs");
    let mut report = Report::default();
    let expanded = Cell::new(0u64);

    for path in &archives {
        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
        let mut archive = archive::open(path, &config.limits)
            .with_context(|| format!("cannot open ZIP {}", path.display()))?;
        let directory = if archives.len() == 1 {
            staging.path().to_path_buf()
        } else {
            let name = path.file_stem().context("ZIP has no filename")?;
            let directory = staging.path().join(name);
            ensure!(
                !directory.try_exists()?,
                "multiple ZIPs have the same archive name"
            );
            security::private_dir(&directory)?;
            directory
        };
        let mut total = 0;
        for index in 0..archive.len() {
            ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
            let entry = archive.by_index_data(index)?;
            let name = entry.name()?;
            extraction::validate_name(&name)?;
            let relative: PathBuf = name
                .split(['/', '\\'])
                .filter(|part| !part.is_empty() && *part != ".")
                .collect();
            if entry.is_dir() {
                let kind = entry.unix_mode().unwrap_or(0) & 0o170000;
                ensure!(
                    kind == 0 || kind == 0o040000,
                    "special archive entry refused"
                );
                private_tree(&directory.join(relative))?;
                continue;
            }
            ensure!(
                !relative.as_os_str().is_empty(),
                "archive entry has no filename"
            );
            let target = directory.join(relative);
            let target_parent = target
                .parent()
                .context("archive entry has no parent directory")?;
            private_tree(target_parent)?;
            ensure!(!target.try_exists()?, "duplicate archive entry path");
            let item = extraction::extract_with_progress(
                &mut archive,
                index,
                &passwords,
                staging.path(),
                &config.limits,
                &mut total,
                cancelled,
                None,
                &|read| {
                    expanded.set(expanded.get().saturating_add(read));
                    progress.streaming_message(|| {
                        format!(
                            "{} files · {} expanded",
                            report.files,
                            bytes(expanded.get())
                        )
                    });
                },
            )
            .with_context(|| format!("ZIP {} entry {index}", path.display()))?;
            security::seal(item.file.as_file(), config.security.mode)?;
            item.file.as_file().sync_all()?;
            item.file.persist_noclobber(&target)?;
            File::open(target_parent)?.sync_all()?;
            report.files += 1;
            report.expanded_bytes = report
                .expanded_bytes
                .checked_add(item.size)
                .context("expanded byte count overflow")?;
        }
        if let Some(verified) = config.verified_inputs.get(path) {
            ensure!(
                pipeline::hash_input(path, cancelled)? == verified.sha256,
                "download changed during extraction"
            );
        }
        report.archives += 1;
        progress.0.set_message(format!(
            "{} files · {} expanded",
            report.files,
            bytes(expanded.get())
        ));
        progress.0.inc(1);
    }
    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
    security::publish_directory(staging.path(), output)?;
    File::open(parent)?.sync_all()?;
    Ok(report)
}
