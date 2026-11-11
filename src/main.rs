//! Runs the BFS command-line application and translates outcomes into process exit codes.
//! The dispatcher connects parsed arguments to configuration, cancellation and library
//! operations. Structured results go to stdout; diagnostics go to stderr so scripts can
//! consume reports without mixing them with progress and error messages.

use anyhow::Result;
use bfsort::{
    app::cli::{Cli, Command},
    app::config::Config,
    app::presentation::{Progress, exit_on_interrupt},
};
use clap::{CommandFactory, FromArgMatches};
/// Dispatch one parsed CLI command and return its process exit code.
fn run(cli: Cli) -> Result<u8> {
    let ui = &cli.presentation;
    bfsort::app::presentation::initialize(ui);
    let started = std::time::Instant::now();
    match cli.command {
        Command::Metadata { command } => {
            use bfsort::app::cli::MetadataCommand;
            let (kind, count) = match command {
                MetadataCommand::Migrate { repository } => {
                    exit_on_interrupt()?;
                    let repo = bfsort::repository::storage::Repository::existing(&repository)?;
                    let progress = Progress::delayed("Migrating catalog");
                    let count = repo.with_catalog(|catalog| {
                        Ok(catalog.counts(&Default::default())?.occurrences)
                    })?;
                    drop(progress);
                    ("Migrated", count)
                }
                MetadataCommand::Import { repository, input } => {
                    exit_on_interrupt()?;
                    let repo = bfsort::repository::storage::Repository::existing(&repository)?;
                    (
                        "Imported",
                        bfsort::repository::metadata::import_catalog(&repo, &input)? as u64,
                    )
                }
            };
            output(
                ui,
                &serde_json::json!({"operation":kind,"occurrences":count}),
                &format!("{kind}: {count} occurrences"),
            )?;
            Ok(0)
        }
        Command::Verify { repository, full } => {
            let report =
                bfsort::repository::verify::run(&repository, full, cancellation()?.as_ref())?;
            output(ui, &report, &report.summary)?;
            Ok(if report.failures.is_empty() { 0 } else { 1 })
        }
        Command::Query {
            repository,
            selection,
            config,
            count,
        } => {
            let repo = bfsort::repository::storage::Repository::existing(&repository)?;
            let selected = filters(&selection, config.as_deref(), ui)?;
            exit_on_interrupt()?;
            if count {
                let progress = Progress::new(None, "Counting catalog records");
                let counts = bfsort::repository::catalog::read(repo.root())?.counts(&selected)?;
                drop(progress);
                output(
                    ui,
                    &counts,
                    &format!(
                        "{} occurrences; {} unique objects",
                        counts.occurrences, counts.unique_objects
                    ),
                )?;
                return Ok(0);
            }
            let records = bfsort::repository::metadata::select(repo.root(), &selected)?;
            if !ui.quiet {
                if ui.json {
                    let unique = records
                        .iter()
                        .map(|r| &r.sha256)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len();
                    let value = serde_json::json!({"occurrences":records.len(),"unique_objects":unique,"rows":records});
                    output(ui, &value, "")?;
                } else {
                    let human = records
                        .iter()
                        .map(|r| {
                            format!(
                                "{}  {}  {}",
                                r.sha256,
                                r.detection.detected_format.as_str(),
                                bfsort::app::presentation::safe_text(&r.original_entry_name)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    output(ui, &(), &human)?;
                }
            }
            Ok(0)
        }
        Command::Diff { left, right } => {
            exit_on_interrupt()?;
            let report = bfsort::repository::compare::run(&left, &right)?;
            output(ui, &report, &serde_json::to_string_pretty(&report)?)?;
            Ok(0)
        }
        Command::Merge {
            repositories,
            output: destination,
            selection,
            config,
            dry_run,
            resume,
        } => derived(
            ui,
            bfsort::repository::derive::Options {
                sources: repositories,
                output: destination,
                kind: bfsort::repository::derive::Kind::Merge,
                dry_run,
                resume,
            },
            selection,
            config,
        ),
        Command::Sample {
            repository,
            count,
            percentage,
            seed,
            stratify,
            unit,
            output: destination,
            selection,
            config,
            dry_run,
            resume,
        } => derived(
            ui,
            bfsort::repository::derive::Options {
                sources: vec![repository],
                output: destination,
                kind: bfsort::repository::derive::Kind::Sample(
                    bfsort::repository::derive::SampleOptions {
                        count,
                        percentage,
                        seed,
                        stratify,
                        unit,
                    },
                ),
                dry_run,
                resume,
            },
            selection,
            config,
        ),
        Command::Split {
            repository,
            by,
            output: destination,
            selection,
            config,
            dry_run,
            resume,
        } => {
            let by = match by {
                bfsort::app::cli::SplitBy::Extension => {
                    bfsort::repository::derive::SplitBy::Extension
                }
                bfsort::app::cli::SplitBy::Format => bfsort::repository::derive::SplitBy::Format,
            };
            derived(
                ui,
                bfsort::repository::derive::Options {
                    sources: vec![repository],
                    output: destination,
                    kind: bfsort::repository::derive::Kind::Split { by },
                    dry_run,
                    resume,
                },
                selection,
                config,
            )
        }
        Command::Status { root } => {
            exit_on_interrupt()?;
            let progress = Progress::delayed("Reading operation status");
            let report = bfsort::operations::status(&root)?;
            drop(progress);
            output(ui, &report, &serde_json::to_string_pretty(&report)?)?;
            Ok(0)
        }
        Command::Retry {
            root,
            operation,
            failed,
            inputs,
        } => {
            let records = bfsort::operations::status(&root)?;
            let record = records
                .iter()
                .find(|r| r.id == operation)
                .ok_or_else(|| anyhow::anyhow!("operation not found"))?;
            let mut recorded =
                bfsort::operations::retry_selected_arguments(&root, &operation, failed, &inputs)?
                    .into_iter();
            let mut args = Vec::new();
            while let Some(arg) = recorded.next() {
                match arg.as_str() {
                    "--color" => {
                        recorded.next();
                    }
                    "--json" | "--quiet" | "--verbose" | "--no-progress" | "--no-color" => {}
                    _ if arg.starts_with("--color=") => {}
                    _ => args.push(arg),
                }
            }
            let mut child = std::process::Command::new(std::env::current_exe()?);
            child
                .env("BFSORT_RETRY_OF", &operation)
                .current_dir(&record.cwd);
            for (enabled, flag) in [
                (ui.json, "--json"),
                (ui.quiet, "--quiet"),
                (ui.verbose, "--verbose"),
                (ui.no_progress, "--no-progress"),
                (ui.no_color, "--no-color"),
            ] {
                if enabled {
                    child.arg(flag);
                }
            }
            child.args([
                "--color",
                match ui.color {
                    bfsort::app::cli::ColorMode::Auto => "auto",
                    bfsort::app::cli::ColorMode::Always => "always",
                    bfsort::app::cli::ColorMode::Never => "never",
                },
            ]);
            let status = child.args(args).status()?;
            Ok(status.code().unwrap_or(1).try_into().unwrap_or(1))
        }
        Command::Remove {
            repository,
            selection,
            config,
            dry_run,
            confirm,
        } => {
            exit_on_interrupt()?;
            let report = bfsort::repository::cleanup::remove(
                &repository,
                &filters(&selection, config.as_deref(), ui)?,
                dry_run,
                confirm,
            )?;
            output(ui, &report, &serde_json::to_string_pretty(&report)?)?;
            Ok(0)
        }
        Command::Prune {
            repository,
            dry_run,
            confirm,
        } => {
            exit_on_interrupt()?;
            let report = bfsort::repository::cleanup::prune(&repository, dry_run, confirm)?;
            output(ui, &report, &serde_json::to_string_pretty(&report)?)?;
            Ok(0)
        }
        Command::Config {
            command: bfsort::app::cli::ConfigCommand::Validate { config },
        } => {
            exit_on_interrupt()?;
            let progress = Progress::delayed("Validating configuration");
            let config = load(config.as_deref(), ui)?;
            config.validate()?;
            drop(progress);
            output(
                ui,
                &serde_json::json!({"valid": true}),
                "Configuration valid",
            )?;
            Ok(0)
        }
        Command::Collect(args) => {
            let config = load(args.config.as_deref(), ui)?;
            let mut source = config.source.unwrap_or_default();
            if let Some(url) = args.url {
                source.page = url;
            }
            let mut download = config.download.unwrap_or_default();
            if let Some(root) = args.output {
                download.inventory = root.join("inventory.json");
                download.staging_dir = root.join("downloads");
            }
            if let Some(workers) = args.workers {
                download.concurrency = workers;
            }
            download.validate()?;
            let cancelled = cancellation()?;
            let mut history = if args.dry_run {
                None
            } else {
                Some(history(collection_root(&download), "collect")?)
            };
            let inventory_path = &download.inventory;
            let inventory = if args.refresh || !inventory_path.try_exists()? {
                if args.dry_run && !ui.quiet && !ui.json {
                    eprintln!("Preview: requesting HTML metadata; no payloads will be downloaded.");
                }
                let inventory =
                    bfsort::collection::http_source::discover(&source, &download, &cancelled)?;
                // A dry run never publishes acquisition state or creates payload storage.
                if !args.dry_run {
                    save_inventory(&download, &inventory)?;
                }
                inventory
            } else {
                bfsort::collection::acquisition::load_inventory(inventory_path)?
            };
            let result = download_inventory(
                ui,
                &download,
                source,
                &inventory,
                args.dry_run,
                &cancelled,
                started,
            );
            if let Some(history) = &mut history {
                history.finish(if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                    130
                } else {
                    *result.as_ref().unwrap_or(&1)
                })?;
            }
            result
        }
        Command::Discover(args) => {
            anyhow::ensure!(
                !args.dry_run,
                "discover performs HTTP requests; use download --dry-run for offline preview"
            );
            let config = load(args.config.as_deref(), ui)?;
            let mut source = config.source.unwrap_or_default();
            if let Some(url) = args.url {
                source.page = url;
            }
            let download = config.download.unwrap_or_default();
            let cancelled = cancellation()?;
            let inventory =
                bfsort::collection::http_source::discover(&source, &download, &cancelled)?;
            save_inventory(&download, &inventory)?;
            let files: Vec<_> = inventory.candidates.iter().map(|c| &c.name).collect();
            if ui.json && !ui.quiet {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({"files": files}))?
                );
            } else if !ui.quiet {
                for name in files {
                    println!("{}", bfsort::app::presentation::safe_text(name));
                }
            }
            Ok(0)
        }
        Command::Download(args) => {
            let config = load(args.config.as_deref(), ui)?;
            let download = config.download.unwrap_or_default();
            let inventory = bfsort::collection::acquisition::load_inventory(&download.inventory)?;
            let mut history = if args.dry_run {
                None
            } else {
                Some(history(collection_root(&download), "download")?)
            };
            let cancelled = cancellation()?;
            let result = download_inventory(
                ui,
                &download,
                config.source.unwrap_or_default(),
                &inventory,
                args.dry_run,
                &cancelled,
                started,
            );
            if let Some(history) = &mut history {
                history.finish(if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                    130
                } else {
                    *result.as_ref().unwrap_or(&1)
                })?;
            }
            result
        }
        Command::Ingest(args) => {
            log_config(args.config.as_deref(), ui);
            let cancelled = cancellation()?;
            let mut config = Config::for_ingest_cancellable(&args, &cancelled)?;
            if ui.verbose {
                effective(&config);
            }
            if args.unzip_only {
                let report = bfsort::ingest::unzip::run(&config, &cancelled)?;
                output(
                    ui,
                    &report,
                    &format!(
                        "Extracted {} files from {} ZIPs ({}) to {}",
                        report.files,
                        report.archives,
                        bfsort::app::presentation::bytes(report.expanded_bytes),
                        bfsort::app::presentation::safe_text(&config.output.display().to_string())
                    ),
                )?;
                return Ok(0);
            }
            if args.dry_run {
                let preview = bfsort::ingest::pipeline::preview(&config, &cancelled)?;
                output(
                    ui,
                    &preview,
                    &format!(
                        "{}\nPreview: {} occurrences; {} unique; {} duplicates; output {}",
                        preview
                            .plan
                            .iter()
                            .map(|e| bfsort::app::presentation::safe_text(&e.planned.path))
                            .collect::<Vec<_>>()
                            .join("\n"),
                        preview.summary.occurrences,
                        preview.summary.unique_files,
                        preview.summary.duplicate_occurrences,
                        bfsort::app::presentation::safe_text(&config.output.display().to_string())
                    ),
                )?;
                return Ok(0);
            }
            if config.archive.nested_extraction
                && (config.archive.max_total_entries.is_none()
                    || config.archive.max_total_expanded_bytes.is_none())
                && !ui.quiet
                && !ui.json
            {
                eprintln!(
                    "Warning: recursive extraction has unlimited tree budgets; configure [archive] limits."
                );
            }
            if !config.zip_enabled() {
                config.operation_args = Some(std::env::args().skip(1).collect());
            }
            let report = bfsort::ingest::pipeline::ingest(&config, &cancelled)?;
            output(
                ui,
                &report,
                &format!(
                    "{}: {} accepted occurrences; {} reused occurrences; {} skipped files; {} failed; {}; {:.2}s; output {}{}",
                    if report.failures > 0 || report.interrupted {
                        "partial"
                    } else {
                        "done"
                    },
                    report.accepted,
                    report.reused_occurrences,
                    report.skipped_files,
                    report.failures,
                    bfsort::app::presentation::bytes(report.summary.logical_bytes),
                    report.elapsed_seconds,
                    bfsort::app::presentation::safe_text(&config.output.display().to_string()),
                    if report.interrupted {
                        "; interrupted"
                    } else {
                        ""
                    }
                ),
            )?;
            if let Some(error) = &report.first_failure {
                eprintln!(
                    "error: {}: {}",
                    bfsort::app::presentation::safe_text(&error.source_path),
                    bfsort::app::presentation::safe_text(&error.error)
                );
            }
            if report.interrupted {
                eprintln!(
                    "Interrupted: {} samples accepted; {} failures",
                    report.accepted, report.failures
                );
            }
            Ok(if report.failures > 0 || report.interrupted {
                if report.accepted + report.reused_occurrences > 0 {
                    2
                } else {
                    1
                }
            } else {
                0
            })
        }
        Command::Inspect(args) => {
            exit_on_interrupt()?;
            let mut config = load(args.config.as_deref(), ui)?;
            if !args.inputs.is_empty() {
                config.inputs = args.inputs;
            }
            if let Some(value) = args.recursive {
                config.recursive = value;
            }
            if config.inputs.is_empty() {
                config
                    .inputs
                    .push(bfsort::app::config::DEFAULT_INPUT_DIRECTORY.into());
            }
            config.validate()?;
            let enumeration = Progress::new(None, "Enumerating archives");
            let archives = bfsort::ingest::discovery::discover(
                &config.inputs,
                config.recursive,
                &config.output,
            )?;
            drop(enumeration);
            let progress = Progress::new(Some(archives.len() as u64), "Inspecting archives");
            let inspections = archives
                .iter()
                .map(|path| {
                    let result = bfsort::output::archive::inspect(path, &config.limits);
                    progress.0.inc(1);
                    result
                })
                .collect::<Result<Vec<_>>>()?;
            drop(progress);
            output(
                ui,
                &inspections,
                &serde_json::to_string_pretty(&inspections)?,
            )?;
            Ok(0)
        }
        Command::Report {
            command: bfsort::app::cli::ReportCommand::Mismatches(args),
        } => {
            exit_on_interrupt()?;
            let repo = bfsort::repository::storage::Repository::existing(&args.repository)?;
            let records = bfsort::repository::metadata::select(
                repo.root(),
                &filters(&args.selection, args.config.as_deref(), ui)?,
            )?;
            let report = bfsort::output::report::mismatches(
                &records,
                &args.status,
                args.min_confidence,
                args.all,
            );
            if report.rows.is_empty()
                && !ui.quiet
                && !ui.json
                && matches!(args.format, bfsort::output::report::ReportFormat::Table)
            {
                if records.is_empty() {
                    eprintln!("No stored occurrences to report.");
                } else if report.counts.get("not_evaluated").copied().unwrap_or(0) > 0 {
                    eprintln!(
                        "Some records were not evaluated; use analyze explicitly on an accessible standard repository."
                    );
                } else if report.counts.get("mismatch").copied().unwrap_or(0) == 0 {
                    eprintln!(
                        "No definitive mismatches. Use --all or --status to inspect other statuses."
                    );
                } else {
                    eprintln!(
                        "All rows were filtered out. Use --all or adjust --status and --min-confidence."
                    );
                }
            }
            let format =
                if ui.json && matches!(args.format, bfsort::output::report::ReportFormat::Table) {
                    bfsort::output::report::ReportFormat::Json
                } else {
                    args.format
                };
            if let Some(path) = args.output {
                bfsort::ingest::discovery::check_path(&path)?;
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(std::path::Path::new("."));
                let mut file = tempfile::NamedTempFile::new_in(parent)?;
                report.write(&mut file, format)?;
                file.as_file().sync_all()?;
                file.persist_noclobber(&path)?;
                std::fs::File::open(parent)?.sync_all()?;
            } else if !ui.quiet || ui.json {
                report.write(std::io::stdout().lock(), format)?;
            }
            Ok(0)
        }
        Command::Analyze {
            selection,
            repository,
            config,
            resume,
            dry_run,
        } => {
            let repo = bfsort::repository::storage::Repository::existing(&repository)?;
            let mut config = load(config.as_deref(), ui)?;
            config.filters = selection.resolve(config.filters)?;
            config.resume = resume;
            config.input_mode = bfsort::app::config::InputMode::Archives;
            config.validate()?;
            if dry_run {
                exit_on_interrupt()?;
                let preview = bfsort::ingest::nested::preview(&repo, &config)?;
                output(
                    ui,
                    &preview,
                    &format!(
                        "Preview: {} archive occurrences; {} unique; {} reusable; {} need extraction; expanded size unknown",
                        preview.candidate_occurrences,
                        preview.unique_archives,
                        preview.reusable_archives,
                        preview.needs_extraction
                    ),
                )?;
                return Ok(0);
            }
            if (config.archive.max_total_entries.is_none()
                || config.archive.max_total_expanded_bytes.is_none())
                && !ui.quiet
                && !ui.json
            {
                eprintln!(
                    "Warning: recursive extraction has unlimited tree budgets; configure [archive] limits."
                );
            }
            anyhow::ensure!(
                bfsort::repository::cleanup::removed(repo.root())?.is_empty(),
                "nested analysis after logical removal requires a fresh repository"
            );
            let mut history = history(repo.root(), "analyze")?;
            let cancelled = cancellation()?;
            let result = bfsort::ingest::nested::analyze(&repo, &config, &cancelled);
            if result.is_err() && cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                history.interrupt()?;
            }
            let report = result?;
            history.record_counts(
                None,
                (report.accepted + report.reused_occurrences) as u64,
                report.failures as u64,
                0,
            )?;
            history.finish(if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                130
            } else if report.failures > 0 {
                1
            } else {
                0
            })?;
            output(
                ui,
                &report,
                &format!(
                    "Analyzed: {} child occurrences; {} failed; {} archives extracted; {} reused",
                    report.accepted,
                    report.failures,
                    report.metrics.extracted_archives,
                    report.metrics.reused_archives
                ),
            )?;
            Ok(if report.failures > 0 { 1 } else { 0 })
        }
        Command::Reclassify {
            selection,
            config,
            repository,
            resume,
            dry_run,
        } => {
            let repo = bfsort::repository::storage::Repository::existing(&repository)?;
            let selected = filters(&selection, config.as_deref(), ui)?;
            if dry_run {
                let rows = bfsort::repository::metadata::select(repo.root(), &selected)?;
                let hashes: std::collections::BTreeSet<_> =
                    rows.iter().map(|r| &r.sha256).collect();
                output(
                    ui,
                    &serde_json::json!({"unique_objects": hashes.len(), "detector_version": bfsort::detection::classifier::DETECTOR_VERSION}),
                    &format!(
                        "Preview: {} unique objects; detector {}",
                        hashes.len(),
                        bfsort::detection::classifier::DETECTOR_VERSION
                    ),
                )?;
                return Ok(0);
            }
            let mut history = history(repo.root(), "reclassify")?;
            let cancelled = cancellation()?;
            let result = bfsort::repository::metadata::reclassify_selected(
                &repo, &cancelled, resume, &selected,
            );
            if result.is_err() && cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                history.interrupt()?;
            }
            let count = result?;
            history.record_counts(Some(count as u64), count as u64, 0, 0)?;
            history.finish(0)?;
            output(
                ui,
                &serde_json::json!({"analyzed_occurrences": count}),
                &format!("Reclassified: {count} occurrences"),
            )?;
            Ok(0)
        }
        Command::Export(args) => {
            let repo = bfsort::repository::storage::Repository::existing(&args.repository)?;
            let rules = bfsort::organization::rules::Rules::load_or_preset(
                args.rules.as_deref(),
                args.preset,
            )?;
            let loaded = load(args.config.as_deref(), ui)?;
            let config = Config {
                compression_level: args.compression_level.or(loaded.compression_level),
                export_naming: args.naming.unwrap_or(loaded.export_naming),
                filters: args.selection.resolve(loaded.filters)?,
                resume: args.resume,
                output: args.output,
                zip: true,
                zip_each_dir: args.zip_each_dir,
                zip_dirs: args.zip_dirs,
                output_password_file: args.output_password_file,
                ..Config::default()
            };
            let mut history = if args.dry_run {
                None
            } else {
                Some(history(repo.root(), "export")?)
            };
            let cancelled = cancellation()?;
            let result = bfsort::output::archive::export_repository(
                &repo,
                &rules,
                &config,
                args.dry_run,
                &cancelled,
            );
            if result.is_err()
                && cancelled.load(std::sync::atomic::Ordering::Relaxed)
                && let Some(history) = &mut history
            {
                history.interrupt()?;
            }
            let exports = result?;
            if let Some(history) = &mut history {
                history.record_counts(Some(exports.len() as u64), exports.len() as u64, 0, 0)?;
                history.finish(0)?;
            }
            output(
                ui,
                &exports,
                &format!(
                    "{}: {} ZIP collections; {} reused; {:.2}s; output {}",
                    if args.dry_run { "Preview" } else { "done" },
                    exports.len(),
                    exports.iter().filter(|export| export.reused).count(),
                    started.elapsed().as_secs_f64(),
                    bfsort::app::presentation::safe_text(&config.output.display().to_string())
                ),
            )?;
            Ok(0)
        }
        Command::Stats {
            repository,
            selection,
            config,
        } => {
            let repo = bfsort::repository::storage::Repository::existing(&repository)?;
            exit_on_interrupt()?;
            let progress = Progress::new(None, "Summarizing catalog");
            let catalog = bfsort::repository::catalog::read(repo.root())?;
            let referenced = catalog.referenced_hashes()?;
            let records = catalog.select(&filters(&selection, config.as_deref(), ui)?, false)?;
            let summary =
                bfsort::output::report::summary_with_references(&repo, &records, &referenced)?;
            drop(progress);
            output(
                ui,
                &summary,
                &bfsort::app::presentation::stats(repo.root(), &summary),
            )?;
            Ok(0)
        }
        Command::Reorganize {
            selection,
            config,
            repository,
            rules,
            preset,
            dry_run,
        } => {
            exit_on_interrupt()?;
            let progress = Progress::new(None, "Building view plan");
            let rules =
                bfsort::organization::rules::Rules::load_or_preset(rules.as_deref(), preset)?;
            let repo = bfsort::repository::storage::Repository::existing(&repository)?;
            let records = bfsort::repository::metadata::select(
                repo.root(),
                &filters(&selection, config.as_deref(), ui)?,
            )?;
            let plan = rules.plan(&records)?;
            drop(progress);
            if dry_run {
                output(ui, &plan, &serde_json::to_string_pretty(&plan)?)?;
            } else {
                let count = bfsort::organization::organizer::organize(&repo, &rules, &plan)?;
                output(ui, &count, &format!("Completed: {count} organized"))?;
            }
            Ok(0)
        }
    }
}
/// Initialize logging, run the CLI, and convert errors into an exit code.
fn main() -> std::process::ExitCode {
    let arguments: Vec<_> = std::env::args_os().collect();
    let mut mode = bfsort::app::cli::ColorMode::Auto;
    for pair in arguments.windows(2) {
        if pair[0] == "--color" {
            mode = match pair[1].to_str() {
                Some("always") => bfsort::app::cli::ColorMode::Always,
                Some("never") => bfsort::app::cli::ColorMode::Never,
                _ => bfsort::app::cli::ColorMode::Auto,
            };
        }
    }
    for arg in &arguments {
        if arg == "--color=always" {
            mode = bfsort::app::cli::ColorMode::Always;
        }
        if arg == "--color=never" {
            mode = bfsort::app::cli::ColorMode::Never;
        }
    }
    let machine_format = arguments
        .windows(2)
        .any(|pair| pair[0] == "--format" && matches!(pair[1].to_str(), Some("json" | "csv")))
        || arguments
            .iter()
            .any(|a| matches!(a.to_str(), Some("--format=json" | "--format=csv")));
    let disabled = machine_format || arguments.iter().any(|a| a == "--no-color" || a == "--json");
    let choice = if disabled {
        clap::ColorChoice::Never
    } else {
        match mode {
            bfsort::app::cli::ColorMode::Always => clap::ColorChoice::Always,
            bfsort::app::cli::ColorMode::Never => clap::ColorChoice::Never,
            bfsort::app::cli::ColorMode::Auto => clap::ColorChoice::Auto,
        }
    };
    let matches = Cli::command().color(choice).get_matches_from(arguments);
    let mut cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    if matches!(&cli.command, Command::Report { command: bfsort::app::cli::ReportCommand::Mismatches(args) } if !matches!(args.format, bfsort::output::report::ReportFormat::Table))
    {
        cli.presentation.json = true;
    }
    bfsort::app::presentation::initialize(&cli.presentation);
    let verbose = cli.presentation.verbose;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
    match run(cli) {
        Ok(code) => std::process::ExitCode::from(code),
        Err(error) => {
            eprintln!(
                "{}: {}",
                bfsort::app::presentation::label("error", "31"),
                bfsort::app::presentation::safe_text(&format!("{error:#}"))
            );
            if verbose {
                eprintln!(
                    "Details: {}",
                    bfsort::app::presentation::safe_text(&format!("{error:#}"))
                );
            }
            std::process::ExitCode::from(1)
        }
    }
}

fn cancellation() -> Result<std::sync::Arc<std::sync::atomic::AtomicBool>> {
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let signal = flag.clone();
    ctrlc::set_handler(move || signal.store(true, std::sync::atomic::Ordering::Relaxed))?;
    Ok(flag)
}

fn log_config(path: Option<&std::path::Path>, ui: &bfsort::app::cli::Presentation) {
    if ui.verbose {
        match Config::active_path(path) {
            Some(path) => eprintln!(
                "Configuration: {}",
                bfsort::app::presentation::safe_text(&path.display().to_string())
            ),
            None => eprintln!("Configuration: built-in defaults"),
        }
    }
}
fn load(path: Option<&std::path::Path>, ui: &bfsort::app::cli::Presentation) -> Result<Config> {
    log_config(path, ui);
    let config = Config::load(path)?;
    if ui.verbose {
        effective(&config);
    }
    Ok(config)
}
fn effective(config: &Config) {
    eprintln!(
        "Settings: output {}; workers {}; resume {}",
        bfsort::app::presentation::safe_text(&config.output.display().to_string()),
        config.workers,
        config.resume
    );
    let size = |value: Option<u64>| {
        value
            .map(bfsort::app::presentation::bytes)
            .unwrap_or_else(|| "unlimited".into())
    };
    eprintln!(
        "Limits: entry {}; archive {}; input {}; entries {}; expansion ratio {}",
        size(config.limits.max_entry_bytes),
        size(config.limits.max_archive_bytes),
        size(config.limits.max_input_bytes),
        config
            .limits
            .max_entries
            .map_or_else(|| "unlimited".into(), |n| n.to_string()),
        config
            .limits
            .max_expansion_ratio
            .map_or_else(|| "unlimited".into(), |n| n.to_string())
    );
    for path in &config.inputs {
        eprintln!(
            "Input: {}",
            bfsort::app::presentation::safe_text(&path.display().to_string())
        );
    }
    if let Some(source) = &config.source {
        eprintln!(
            "Discovery: page {}; timeout {}",
            size(source.max_page_size),
            source
                .timeout_seconds
                .map_or_else(|| "disabled".into(), |n| format!("{n}s"))
        );
    }
    if let Some(download) = &config.download {
        eprintln!(
            "Download budgets: file {}; total {}; staging {}; files {}; requests {}",
            size(download.max_file_size),
            size(download.max_total_size),
            size(download.max_staging_size),
            download
                .max_files
                .map_or_else(|| "unlimited".into(), |n| n.to_string()),
            download
                .max_requests
                .map_or_else(|| "unlimited".into(), |n| n.to_string())
        );
        eprintln!(
            "Download: inventory {}; staging {}; workers {}; timeout {}",
            bfsort::app::presentation::safe_text(&download.inventory.display().to_string()),
            bfsort::app::presentation::safe_text(&download.staging_dir.display().to_string()),
            download.concurrency,
            download
                .timeout_seconds
                .map_or_else(|| "disabled".into(), |n| format!("{n}s"))
        );
    }
}
fn output(
    ui: &bfsort::app::cli::Presentation,
    value: &impl serde::Serialize,
    human: &str,
) -> Result<()> {
    if ui.quiet {
        return Ok(());
    }
    if ui.json {
        println!("{}", serde_json::to_string(value)?);
    } else if !ui.quiet {
        use std::io::IsTerminal;
        if bfsort::app::presentation::color_enabled(
            ui.color,
            ui.no_color,
            ui.json,
            std::io::stdout().is_terminal(),
            std::env::var_os("NO_COLOR").is_some(),
        ) {
            for line in human.lines() {
                let boundary = line.find(char::is_whitespace).unwrap_or(line.len());
                let (label, rest) = line.split_at(boundary);
                let code = match label.trim_end_matches(':') {
                    "partial" => Some("33"),
                    "done" | "Completed" => Some("32"),
                    "Preview" | "Repository" | "Samples" | "Duplicates" | "Stored" | "Logical"
                    | "Mismatches" | "Detected" | "Mismatch" | "Configuration" => Some("36"),
                    _ => None,
                };
                if let Some(code) = code {
                    println!("\x1b[1;{code}m{label}\x1b[0m{rest}");
                } else {
                    println!("{line}");
                }
            }
        } else {
            println!("{human}");
        }
    }
    Ok(())
}
fn save_inventory(
    download: &bfsort::collection::acquisition::DownloadConfig,
    inventory: &bfsort::collection::acquisition::Inventory,
) -> Result<()> {
    let parent = download
        .inventory
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    bfsort::collection::acquisition::private_tree(parent)?;
    bfsort::collection::acquisition::save_json(&download.inventory, inventory)
}
fn download_inventory(
    ui: &bfsort::app::cli::Presentation,
    download: &bfsort::collection::acquisition::DownloadConfig,
    mut source: bfsort::collection::acquisition::SourceConfig,
    inventory: &bfsort::collection::acquisition::Inventory,
    dry_run: bool,
    cancelled: &std::sync::atomic::AtomicBool,
    started: std::time::Instant,
) -> Result<u8> {
    let report = if dry_run || inventory.candidates.is_empty() {
        bfsort::collection::download::preview(download, inventory)?
    } else {
        if source.page.is_empty() {
            source.page = inventory.candidates[0].url.clone();
        }
        bfsort::collection::download::run(download, &source, inventory, cancelled)?
    };
    output(
        ui,
        &report,
        &format!(
            "{}: {} downloaded; {} cached; {} failed; {} pending; {} selected; {} filtered; {}; {:.2}s; output {}",
            if dry_run {
                "Preview"
            } else if report.failed + report.not_attempted > 0 {
                "partial"
            } else {
                "done"
            },
            report.downloaded,
            report.cached,
            report.failed,
            report.not_attempted,
            report.candidates.len(),
            report.filtered,
            bfsort::app::presentation::bytes(report.bytes),
            started.elapsed().as_secs_f64(),
            bfsort::app::presentation::safe_text(&download.staging_dir.display().to_string())
        ),
    )?;
    if !ui.quiet && !ui.json && !dry_run {
        eprintln!(
            "hint: downloads are not an ingested repository. With configured receipts and authorized payload access, use bfsort ingest --extract; otherwise specify accessible input paths explicitly."
        );
    }
    for error in &report.errors {
        eprintln!("error: {}", bfsort::app::presentation::safe_text(error));
    }
    Ok(if report.failed + report.not_attempted == 0 {
        0
    } else if report.downloaded + report.cached > 0 {
        2
    } else {
        1
    })
}

fn filters(
    selection: &bfsort::selection::Selection,
    path: Option<&std::path::Path>,
    ui: &bfsort::app::cli::Presentation,
) -> Result<bfsort::selection::Filters> {
    let config = load(path, ui)?;
    config.validate()?;
    selection.resolve(config.filters)
}

fn derived(
    ui: &bfsort::app::cli::Presentation,
    options: bfsort::repository::derive::Options,
    selection: bfsort::selection::Selection,
    config: Option<std::path::PathBuf>,
) -> Result<u8> {
    let report = bfsort::repository::derive::run(
        &options,
        &filters(&selection, config.as_deref(), ui)?,
        cancellation()?.as_ref(),
    )?;
    output(ui, &report, &serde_json::to_string_pretty(&report)?)?;
    Ok(0)
}

fn collection_root(download: &bfsort::collection::acquisition::DownloadConfig) -> &std::path::Path {
    download
        .inventory
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."))
}

fn history(root: &std::path::Path, command: &str) -> Result<bfsort::operations::Guard> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut guard = bfsort::operations::Guard::start(root, command, &args)?;
    if let Ok(id) = std::env::var("BFSORT_RETRY_OF") {
        guard.set_retry_of(&id)?;
    }
    Ok(guard)
}
