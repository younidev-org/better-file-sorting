// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Declares the public command-line interface and clap argument metadata.
//! Commands separate discovery, download, ingest, inspection, statistics and reorganization.
//! Parsing does not perform filesystem or network work; main dispatches commands and
//! configuration merging resolves optional overrides before the pipeline runs.

use crate::app::config::SecurityMode;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "bfsort",
    version,
    styles = styles(),
    after_help = "Workflow: collect → ingest --extract → stats/report → export\ncollect stores downloads, not a repository. Sealed downloads require explicit authorized access before ingestion.\nRepositories default to sealed metadata-only access; choose --security-mode standard before ingestion if payload export is required.",
    about = "Sort files or ZIP samples by metadata without executing their contents"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[command(flatten)]
    pub presentation: Presentation,
}
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Migrate repository metadata or import legacy JSONL without copying payloads
    Metadata {
        #[command(subcommand)]
        command: MetadataCommand,
    },
    /// Verify stored identities, references and object integrity without repairing
    Verify {
        #[arg(default_value = crate::app::config::DEFAULT_REPOSITORY)]
        repository: PathBuf,
        #[arg(long)]
        full: bool,
    },
    /// Search effective occurrence metadata without opening payloads
    Query {
        #[arg(default_value = crate::app::config::DEFAULT_REPOSITORY)]
        repository: PathBuf,
        #[command(flatten)]
        selection: crate::selection::Selection,
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        #[arg(long)]
        count: bool,
    },
    /// Compare unique content, occurrence counts and detection metadata
    Diff { left: PathBuf, right: PathBuf },
    /// Combine standard repositories into a new independent repository
    Merge {
        #[arg(required = true, num_args = 2..)]
        repositories: Vec<PathBuf>,
        #[arg(short = 'o', long)]
        output: PathBuf,
        #[command(flatten)]
        selection: crate::selection::Selection,
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
        /// Verify and reuse completed copies from an interrupted operation
        #[arg(long)]
        resume: bool,
    },
    /// Select a reproducible subset into a new independent repository
    Sample {
        repository: PathBuf,
        #[arg(
            long,
            required_unless_present = "percentage",
            conflicts_with = "percentage"
        )]
        count: Option<usize>,
        #[arg(long, conflicts_with = "count")]
        percentage: Option<f64>,
        /// Proportional strata: ingestion date or detected format family
        #[arg(long, value_enum, value_delimiter = ',')]
        stratify: Vec<crate::repository::derive::Stratum>,
        #[arg(long, value_enum, default_value = "unique-hash")]
        unit: crate::repository::derive::SamplingUnit,
        #[arg(long, default_value_t = 0)]
        seed: u64,
        #[arg(short = 'o', long)]
        output: PathBuf,
        #[command(flatten)]
        selection: crate::selection::Selection,
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
        /// Verify and reuse completed copies from an interrupted operation
        #[arg(long)]
        resume: bool,
    },
    /// Partition a standard repository into independent repositories
    Split {
        repository: PathBuf,
        #[arg(long, value_enum)]
        by: SplitBy,
        #[arg(short = 'o', long)]
        output: PathBuf,
        #[command(flatten)]
        selection: crate::selection::Selection,
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
        /// Verify and reuse completed copies from an interrupted operation
        #[arg(long)]
        resume: bool,
    },
    /// Show recorded operation history and current ownership
    Status { root: PathBuf },
    /// Retry a recorded operation through its verified resume path
    Retry {
        root: PathBuf,
        #[arg(long)]
        operation: String,
        /// Retry only failed, interrupted or unstarted recorded inputs
        #[arg(long)]
        failed: bool,
        /// Retry these recorded ingestion inputs; repeat to select several
        #[arg(long = "input")]
        inputs: Vec<PathBuf>,
    },
    /// Logically remove selected occurrences; retained generations still pin data
    Remove {
        repository: PathBuf,
        #[command(flatten)]
        selection: crate::selection::Selection,
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        #[arg(long, conflicts_with = "confirm")]
        dry_run: bool,
        #[arg(long)]
        confirm: bool,
    },
    /// Reclaim canonical objects unreferenced by retained metadata
    Prune {
        repository: PathBuf,
        #[arg(long, conflicts_with = "confirm")]
        dry_run: bool,
        #[arg(long)]
        confirm: bool,
    },
    /// Discover if needed, select and download into sealed staging
    Collect(Collect),
    /// Validate configuration without processing inputs
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Discover direct ZIP links from an HTTP page
    Discover(Discover),
    /// Download policy-selected ZIPs into sealed staging
    Download(Acquire),
    /// Classify and sort archive contents or ordinary files; optionally ZIP the output
    Ingest(Ingest),
    /// Inspect archive metadata without extracting payloads
    Inspect(Inspect),
    /// Summarize stored metadata without reading payloads
    Stats {
        #[command(flatten)]
        selection: crate::selection::Selection,
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Repository to summarize; defaults to ./organized
        #[arg(default_value = crate::app::config::DEFAULT_REPOSITORY)]
        repository: PathBuf,
    },
    /// Report filename/content inconsistencies from stored metadata
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    /// Extract nested ZIP samples from an existing standard repository
    Analyze {
        #[command(flatten)]
        selection: crate::selection::Selection,
        /// Configuration for nested extraction and per-tree budgets
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Continue with verified archive extraction receipts
        #[arg(long)]
        resume: bool,
        /// Preview candidates and limits without extracting or writing
        #[arg(long)]
        dry_run: bool,
        #[arg(default_value = crate::app::config::DEFAULT_REPOSITORY)]
        repository: PathBuf,
    },
    /// Refresh detection metadata without extracting archives
    Reclassify {
        #[command(flatten)]
        selection: crate::selection::Selection,
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        #[arg(default_value = crate::app::config::DEFAULT_REPOSITORY)]
        repository: PathBuf,
        /// Reuse detection checkpoints after verifying stored object hashes
        #[arg(long)]
        resume: bool,
        /// Show unique-object count and target detector without writing
        #[arg(long)]
        dry_run: bool,
    },
    /// Export an independent ZIP layout using existing objects and metadata
    Export(Export),
    /// Build a new view from metadata without unlocking payloads
    Reorganize {
        #[command(flatten)]
        selection: crate::selection::Selection,
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        #[arg(default_value = crate::app::config::DEFAULT_REPOSITORY)]
        repository: PathBuf,
        #[arg(long)]
        rules: Option<PathBuf>,
        #[arg(long, conflicts_with = "rules")]
        preset: Option<crate::organization::rules::Preset>,
        #[arg(long)]
        dry_run: bool,
    },
}
#[derive(Debug, Args)]
pub struct Ingest {
    /// Export archive samples with safe, original or detected filename suffixes
    #[arg(long, value_enum)]
    pub naming: Option<crate::organization::rules::ExportNaming>,
    /// ZIP compression: 0 stores entries, 1 is fastest, 9 compresses most
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=9))]
    pub compression_level: Option<u8>,
    #[command(flatten)]
    pub selection: crate::selection::Selection,
    /// Verify and reuse completed work from an earlier run
    #[arg(long)]
    pub resume: bool,
    /// Sort ordinary files (default), or explicitly select archives
    #[arg(long, value_enum)]
    pub input_mode: Option<crate::app::config::InputMode>,
    /// Extract ZIP contents using bounded archive processing
    #[arg(long, conflicts_with = "input_mode")]
    pub extract: bool,
    /// Publish only a compressed ZIP at --output, leaving sources untouched
    #[arg(long)]
    pub zip: bool,
    /// ZIP only this sorted relative directory; repeat to select several
    #[arg(long = "zip-dir", value_name = "DIRECTORY")]
    pub zip_dirs: Vec<String>,
    /// Create one ZIP per selected directory or automatic output group
    #[arg(long)]
    pub zip_each_dir: bool,
    /// Protected file containing exactly one password for AES-256 ZIP output
    #[arg(long)]
    pub output_password_file: Option<PathBuf>,
    /// Existing directory for private ZIP and preview temporary storage
    #[arg(long)]
    pub staging_dir: Option<PathBuf>,
    pub inputs: Vec<PathBuf>,
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
    /// Custom sorting rules; choose this or --preset
    #[arg(long)]
    pub rules: Option<PathBuf>,
    /// Embedded grouping: defaults to by-format when no rules are supplied
    #[arg(long, conflicts_with = "rules")]
    pub preset: Option<crate::organization::rules::Preset>,
    #[arg(short = 'j', long)]
    pub workers: Option<usize>,
    #[arg(long)]
    pub password_file: Option<PathBuf>,
    #[arg(long, value_enum)]
    pub security_mode: Option<SecurityMode>,
    #[arg(long, action = clap::ArgAction::Set)]
    pub recursive: Option<bool>,
    /// Hash and classify inputs to preview the final layout without publishing
    #[arg(long)]
    pub dry_run: bool,
}
#[derive(Debug, Args)]
pub struct Inspect {
    pub inputs: Vec<PathBuf>,
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,
    #[arg(long, action = clap::ArgAction::Set)]
    pub recursive: Option<bool>,
}

#[derive(Debug, Args)]
pub struct Acquire {
    /// Verify and reuse completed work from an earlier run
    #[arg(long)]
    pub resume: bool,
    /// Optional runtime TOML; defaults read ./collection/inventory.json
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub dry_run: bool,
}

/// Discovery accepts a direct page URL, optional runtime overrides, or both.
#[derive(Debug, Args)]
pub struct Discover {
    /// HTTP(S) page URL; overrides source.page when a config is supplied
    pub url: Option<String>,
    /// Optional runtime TOML; omitted settings use built-in acquisition defaults
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,
    /// Discovery requires network access; use download --dry-run for offline selection
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct Collect {
    /// Verify and reuse completed work from an earlier run
    #[arg(long)]
    pub resume: bool,
    /// HTTP(S) page; omitted when source.page is configured
    pub url: Option<String>,
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,
    /// Collection root containing inventory.json and downloads/
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
    #[arg(short = 'j', long)]
    pub workers: Option<usize>,
    /// Rediscover instead of reusing the saved inventory
    #[arg(long)]
    pub refresh: bool,
    /// Select without payload requests; missing inventory requires an HTML metadata request
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Check TOML fields and security/limit settings
    Validate {
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Debug, Args)]
pub struct Presentation {
    /// Suppress progress while retaining normal command output
    #[arg(long, global = true)]
    pub no_progress: bool,
    #[arg(long, global = true, value_enum, default_value = "auto")]
    pub color: ColorMode,
    /// Disable color (takes precedence over --color)
    #[arg(long, global = true)]
    pub no_color: bool,
    /// Suppress normal output; errors remain visible
    #[arg(long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,
    /// Show effective settings and diagnostic details
    #[arg(long, global = true)]
    pub verbose: bool,
    /// Machine-readable stdout; disables ANSI and progress on both streams
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum ReportCommand {
    Mismatches(MismatchArgs),
}
#[derive(Debug, Args)]
pub struct MismatchArgs {
    #[command(flatten)]
    pub selection: crate::selection::Selection,
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,
    #[arg(default_value = crate::app::config::DEFAULT_REPOSITORY)]
    pub repository: PathBuf,
    #[arg(long, value_enum, default_value = "table")]
    pub format: crate::output::report::ReportFormat,
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
    #[arg(long, value_enum, value_delimiter = ',')]
    pub status: Vec<crate::detection::mismatch::Status>,
    #[arg(long, value_enum, default_value = "unknown")]
    pub min_confidence: crate::detection::classifier::Confidence,
    /// Include all statuses; --status takes precedence
    #[arg(long)]
    pub all: bool,
}
#[derive(Debug, Args)]
pub struct Export {
    /// Export archive samples with safe, original or detected filename suffixes
    #[arg(long, value_enum)]
    pub naming: Option<crate::organization::rules::ExportNaming>,
    /// ZIP compression: 0 stores entries, 1 is fastest, 9 compresses most
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=9))]
    pub compression_level: Option<u8>,
    #[command(flatten)]
    pub selection: crate::selection::Selection,
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,
    /// Verify and reuse completed work from an earlier run
    #[arg(long)]
    pub resume: bool,
    #[arg(default_value = crate::app::config::DEFAULT_REPOSITORY)]
    pub repository: PathBuf,
    /// Custom sorting rules; choose this or --preset
    #[arg(long)]
    pub rules: Option<PathBuf>,
    /// Embedded grouping: defaults to by-format when no rules are supplied
    #[arg(long, conflicts_with = "rules")]
    pub preset: Option<crate::organization::rules::Preset>,
    /// Destination ZIP, or collection directory with --zip-each-dir
    #[arg(short = 'o', long)]
    pub output: PathBuf,
    /// Create one ZIP per group; automatic fallback uses each full group directory
    #[arg(long)]
    pub zip_each_dir: bool,
    /// Select a sorted relative directory; repeat to select several
    #[arg(long = "zip-dir")]
    pub zip_dirs: Vec<String>,
    /// Private 0600 file containing one AES-256 output password
    #[arg(long)]
    pub output_password_file: Option<PathBuf>,
    /// Preview stored-metadata layout without writing output or opening payloads
    #[arg(long)]
    pub dry_run: bool,
}

fn styles() -> clap::builder::Styles {
    use clap::builder::styling::AnsiColor;
    clap::builder::Styles::styled()
        .header(AnsiColor::Cyan.on_default().bold())
        .usage(AnsiColor::Cyan.on_default().bold())
        .literal(AnsiColor::Green.on_default().bold())
        .placeholder(AnsiColor::Cyan.on_default())
        .error(AnsiColor::Red.on_default().bold())
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum SplitBy {
    Extension,
    Format,
}

#[derive(Debug, Subcommand)]
pub enum MetadataCommand {
    /// Atomically import a legacy repository into its private SQLite catalog
    Migrate { repository: PathBuf },
    /// Import validated JSONL occurrences; referenced objects must already exist
    Import { repository: PathBuf, input: PathBuf },
}
