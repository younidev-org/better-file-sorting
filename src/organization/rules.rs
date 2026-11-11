//! Parses organization policies and resolves occurrence metadata into destination plans.
//! Matching, filename templates and duplicate handling are applied deterministically.
//! Path and collision checks protect publication, while archive-derived records retain
//! the stricter sample filename policy even when other inputs use regular filenames.

use crate::repository::metadata::Occurrence;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use unicode_normalization::UnicodeNormalization;

/// Embedded grouping policies preserve every source occurrence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Preset {
    #[default]
    ByFormat,
    ByFormatOrExtension,
    ByExtension,
    ByMismatch,
}

/// Payload suffix selection is confined to explicit ZIP exports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ExportNaming {
    #[default]
    Sample,
    Original,
    Detected,
}

fn export_extension(row: &Occurrence, naming: ExportNaming) -> String {
    use crate::detection::classifier::Format;
    match naming {
        ExportNaming::Sample => "sample".into(),
        ExportNaming::Original => {
            let extension =
                crate::detection::mismatch::normalize_extension(&row.original_extension);
            if extension.is_empty() {
                "sample".into()
            } else {
                sanitize(&extension)
            }
        }
        ExportNaming::Detected => match row.detection.detected_format {
            Format::NotEvaluated | Format::Unknown | Format::Ambiguous => "sample",
            Format::Pe => "exe",
            Format::Javascript => "js",
            Format::Powershell => "ps1",
            Format::Python => "py",
            Format::Shell => "sh",
            Format::Batch => "bat",
            Format::Text => "txt",
            Format::Gzip => "gz",
            Format::Bzip2 => "bz2",
            Format::Jpeg => "jpg",
            Format::Tiff => "tif",
            Format::JavaClass => "class",
            Format::Zstd => "zst",
            format => format.as_str(),
        }
        .into(),
    }
}

fn deserialize_rule_bytes<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<u64>, D::Error> {
    Option::<crate::collection::acquisition::Quantity>::deserialize(d)?
        .map(|value| value.bytes())
        .transpose()
}

const FIELDS: &[&str] = &[
    "file_type",
    "detected_format",
    "format_or_extension",
    "detected_family",
    "mismatch_status",
    "original_name",
    "original_stem",
    "original_extension",
    "sha256",
    "size",
    "encrypted",
    "duplicate",
    "source_archive",
    "ingest_date",
    "occurrence_id",
];
#[derive(Debug, Clone, Serialize)]
pub struct Planned {
    pub path: String,
    pub sha256: String,
    pub occurrence_id: String,
}
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Duplicates {
    #[default]
    FirstOnly,
    All,
    OnlyDuplicates,
    Separate,
}
#[derive(Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewMode {
    #[default]
    Hardlink,
    Manifest,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilenamePolicy {
    #[default]
    Samples,
    Regular,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Organization {
    pub filename_policy: FilenamePolicy,
    pub duplicates: Duplicates,
    pub view_mode: ViewMode,
    pub default_directory: String,
    pub default_filename: String,
}
impl Default for Organization {
    /// Return default duplicate handling and safe sample templates.
    fn default() -> Self {
        Self {
            filename_policy: FilenamePolicy::Samples,
            duplicates: Duplicates::FirstOnly,
            view_mode: ViewMode::Hardlink,
            default_directory: "{file_type}".into(),
            default_filename: "{sha256}.sample".into(),
        }
    }
}
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Matcher {
    pub detected_format: Option<crate::detection::classifier::Format>,
    pub mismatch_status: Option<crate::detection::mismatch::Status>,
    pub file_type: Option<String>,
    pub original_extension: Option<String>,
    pub encrypted: Option<bool>,
    pub duplicate: Option<bool>,
    /// File-size bound as integer bytes or a readable size such as "2 MiB".
    #[serde(deserialize_with = "deserialize_rule_bytes")]
    pub min_size: Option<u64>,
    /// File-size bound as integer bytes or a readable size such as "2 MiB".
    #[serde(deserialize_with = "deserialize_rule_bytes")]
    pub max_size: Option<u64>,
}
impl Matcher {
    /// Check whether this matcher accepts one occurrence.
    fn matches(&self, row: &Occurrence, duplicate: bool) -> bool {
        self.detected_format
            .is_none_or(|v| v == row.detection.detected_format)
            && self
                .mismatch_status
                .is_none_or(|v| v == row.mismatch.status)
            && self.file_type.as_ref().is_none_or(|v| v == &row.file_type)
            && self
                .original_extension
                .as_ref()
                .is_none_or(|v| v.eq_ignore_ascii_case(&row.original_extension))
            && self.encrypted.is_none_or(|v| v == row.encrypted)
            && self.duplicate.is_none_or(|v| v == duplicate)
            && self.min_size.is_none_or(|v| row.size >= v)
            && self.max_size.is_none_or(|v| row.size <= v)
    }
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    pub directory: String,
    pub filename: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default, rename = "match")]
    pub matcher: Matcher,
    pub output: Output,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    pub version: u32,
    pub organization: Organization,
    pub rules: Vec<Rule>,
}
impl Default for Rules {
    /// Return a version-one ruleset with its fallback organization.
    fn default() -> Self {
        Self {
            version: 1,
            organization: Organization::default(),
            rules: vec![],
        }
    }
}
/// Validate a directory or filename template and its placeholders.
fn template(text: &str, filename: bool, policy: FilenamePolicy) -> Result<()> {
    ensure!(
        !text.is_empty() && text.len() <= 1024,
        "empty or overlong template"
    );
    ensure!(
        !text.starts_with('/')
            && !text.contains(['\\', ':'])
            && !text.chars().any(char::is_control),
        "unsafe template path"
    );
    ensure!(
        !text
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == ".."),
        "unsafe template component"
    );
    ensure!(
        text.split('/').count() + text.matches("{format_or_extension}").count() <= 8,
        "directory template exceeds 8 components"
    );
    if filename {
        ensure!(
            !text.contains('/') && (policy == FilenamePolicy::Regular || text.ends_with(".sample")),
            "filename must be one component ending in .sample under the samples policy"
        );
    }
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        ensure!(!rest[..start].contains('}'), "unmatched template brace");
        let end = rest[start + 1..]
            .find('}')
            .ok_or_else(|| anyhow::anyhow!("unmatched template brace"))?
            + start
            + 1;
        ensure!(
            FIELDS.contains(&&rest[start + 1..end]),
            "unknown template placeholder"
        );
        ensure!(
            !filename || &rest[start + 1..end] != "format_or_extension",
            "format_or_extension is a directory-only placeholder"
        );
        rest = &rest[end + 1..];
    }
    ensure!(!rest.contains('}'), "unmatched template brace");
    Ok(())
}
/// Normalize metadata into a safe single path component.
pub fn sanitize(value: &str) -> String {
    let normalized: String = value
        .nfc()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let mut result = String::new();
    for c in normalized.trim_matches([' ', '.']).chars() {
        if result.len() + c.len_utf8() > 120 {
            break;
        }
        result.push(c);
    }
    if result.is_empty() {
        result.push('_');
    }
    let stem = result.split('.').next().unwrap_or("").to_ascii_uppercase();
    if [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "COM¹",
        "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
    ]
    .contains(&stem.as_str())
    {
        result.insert(0, '_');
    }
    result
}

/// Leave room for collision identifiers while retaining an ordinary file's extension.
fn regular_filename(value: &str) -> String {
    let extension = Path::new(value).extension().and_then(|s| s.to_str());
    match extension.filter(|s| !s.is_empty()) {
        Some(extension) => {
            let stem = &value[..value.len() - extension.len() - 1];
            let extension = sanitize(extension);
            let mut stem = sanitize(stem);
            while stem.len() + extension.len() + 1 > 180 {
                stem.pop();
            }
            format!("{stem}.{extension}")
        }
        None => sanitize(value),
    }
}
/// Keep filename fallback visibly separate from content-based classification.
fn format_or_extension(row: &Occurrence) -> String {
    use crate::detection::classifier::{Confidence, Format};
    let detection = &row.detection;
    if detection.detected_format == Format::Ambiguous {
        return "ambiguous".into();
    }
    if !matches!(
        detection.detected_format,
        Format::Unknown | Format::NotEvaluated
    ) && detection.confidence >= Confidence::Medium
    {
        return format!("detected/{}", detection.detected_format.as_str());
    }
    let extension = crate::detection::mismatch::normalize_extension(&row.original_extension);
    let extension = sanitize(&extension);
    if extension == "_" {
        "undetected/no-extension".into()
    } else {
        format!("undetected/extension-{extension}")
    }
}
/// Render a validated template using one occurrence's metadata.
fn render(text: &str, row: &Occurrence, duplicate: bool, policy: FilenamePolicy) -> String {
    let mut result = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        result.push_str(&rest[..start]);
        let end = rest[start..].find('}').expect("validated template") + start;
        let value = match &rest[start + 1..end] {
            "file_type" => row.file_type.clone(),
            "detected_format" => row.detection.detected_format.as_str().into(),
            "format_or_extension" => format_or_extension(row),
            "detected_family" => row.detection.detected_family.as_str().into(),
            "mismatch_status" => row.mismatch.status.as_str().into(),
            "original_name" => row.original_name.clone(),
            "original_stem" => row.original_stem.clone(),
            "original_extension" => row.original_extension.clone(),
            "sha256" => row.sha256.clone(),
            "size" => row.size.to_string(),
            "encrypted" => row.encrypted.to_string(),
            "duplicate" => duplicate.to_string(),
            "source_archive" => row.source_archive.clone(),
            "ingest_date" => row.ingest_date.clone(),
            "occurrence_id" => row.occurrence_id.clone(),
            _ => unreachable!("validated template"),
        };
        if &rest[start + 1..end] == "format_or_extension" {
            result.push_str(&value);
        } else if policy == FilenamePolicy::Regular && &rest[start + 1..end] == "original_name" {
            result.push_str(&regular_filename(&value));
        } else {
            result.push_str(&sanitize(&value));
        }
        rest = &rest[end + 1..];
    }
    result.push_str(rest);
    result
}
impl Rules {
    pub fn uses_format_fallback(&self) -> bool {
        self.organization
            .default_directory
            .contains("{format_or_extension}")
            || self
                .rules
                .iter()
                .any(|rule| rule.output.directory.contains("{format_or_extension}"))
    }
    pub fn for_preset(preset: Preset) -> Self {
        let directory = match preset {
            Preset::ByFormat => "{detected_format}",
            Preset::ByFormatOrExtension => "{format_or_extension}",
            Preset::ByExtension => "{original_extension}",
            Preset::ByMismatch => "{mismatch_status}",
        };
        Self {
            organization: Organization {
                default_directory: directory.into(),
                duplicates: Duplicates::All,
                ..Organization::default()
            },
            ..Self::default()
        }
    }
    pub fn load_or_preset(path: Option<&Path>, preset: Option<Preset>) -> Result<Self> {
        ensure!(
            path.is_none() || preset.is_none(),
            "choose --rules or --preset, not both"
        );
        match path {
            Some(path) => Self::load(Some(path)),
            None => Ok(Self::for_preset(preset.unwrap_or_default())),
        }
    }

    /// Parse and validate a TOML rules document.
    pub fn parse(text: &str) -> Result<Self> {
        let result: Self = toml::from_str(text).map_err(|_| {
            anyhow::anyhow!("invalid rules TOML, unknown field, or unsupported value")
        })?;
        result.validate()?;
        Ok(result)
    }
    /// Load rules from an optional file or return defaults.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(path) => Self::parse(&std::fs::read_to_string(path)?),
            None => Ok(Self::default()),
        }
    }
    /// Validate rule version, templates, matchers, and output constraints.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported rules version");
        let policy = self.organization.filename_policy;
        template(&self.organization.default_directory, false, policy)?;
        template(&self.organization.default_filename, true, policy)?;
        for rule in &self.rules {
            ensure!(!rule.name.trim().is_empty(), "rule name must not be empty");
            template(&rule.output.directory, false, policy)?;
            template(&rule.output.filename, true, policy)?;
            ensure!(
                rule.matcher.min_size.unwrap_or(0) <= rule.matcher.max_size.unwrap_or(u64::MAX),
                "invalid size range"
            );
            if let Some(kind) = &rule.matcher.file_type {
                ensure!(
                    [
                        "pe", "elf", "macho", "pdf", "zip", "text", "other", "unknown"
                    ]
                    .contains(&kind.as_str()),
                    "unsupported file type"
                );
            }
        }
        Ok(())
    }
    /// Build a deterministic, collision-safe logical view plan.
    pub fn plan(&self, records: &[Occurrence]) -> Result<Vec<Planned>> {
        self.plan_named(records, None)
    }

    /// Keep grouping and duplicate policy while opting into ordinary payload suffixes.
    pub fn plan_export(
        &self,
        records: &[Occurrence],
        naming: ExportNaming,
    ) -> Result<Vec<Planned>> {
        self.plan_named(records, (naming != ExportNaming::Sample).then_some(naming))
    }

    fn plan_named(
        &self,
        records: &[Occurrence],
        naming: Option<ExportNaming>,
    ) -> Result<Vec<Planned>> {
        self.validate()?;
        ensure!(
            naming.is_some()
                || self.organization.filename_policy == FilenamePolicy::Samples
                || records
                    .iter()
                    .all(|r| r.input_mode == crate::app::config::InputMode::Files),
            "regular filename policy is forbidden for archive-derived records"
        );
        let mut sorted: Vec<_> = records.iter().collect();
        sorted.sort_by(|a, b| {
            (&a.source_path, a.entry_index, &a.occurrence_id).cmp(&(
                &b.source_path,
                b.entry_index,
                &b.occurrence_id,
            ))
        });
        let mut counts = BTreeMap::new();
        for row in &sorted {
            row.validate()?;
            *counts.entry(&row.sha256).or_insert(0usize) += 1;
        }
        let mut seen = BTreeSet::new();
        let mut paths = BTreeSet::from(["export.json".to_string()]);
        let mut directories = BTreeSet::new();
        let mut result = vec![];
        for row in sorted {
            let duplicate = counts[&row.sha256] > 1;
            let first = seen.insert(&row.sha256);
            if matches!(self.organization.duplicates, Duplicates::FirstOnly) && !first
                || matches!(self.organization.duplicates, Duplicates::OnlyDuplicates) && !duplicate
            {
                continue;
            }
            let output = self
                .rules
                .iter()
                .find(|rule| rule.matcher.matches(row, duplicate))
                .map(|r| &r.output);
            let directory = output.map_or(self.organization.default_directory.as_str(), |o| {
                &o.directory
            });
            let filename =
                output.map_or(self.organization.default_filename.as_str(), |o| &o.filename);
            let directory = render(directory, row, duplicate, self.organization.filename_policy)
                .split('/')
                .map(|p| sanitize(p).to_lowercase())
                .collect::<Vec<_>>()
                .join("/");
            let filename = render(filename, row, duplicate, self.organization.filename_policy);
            let filename = if let Some(naming) = naming {
                regular_filename(&format!(
                    "{}.{}",
                    sanitize(&row.original_stem),
                    export_extension(row, naming)
                ))
            } else if self.organization.filename_policy == FilenamePolicy::Samples {
                format!(
                    "{}.sample",
                    sanitize(filename.strip_suffix(".sample").expect("validated suffix"))
                )
            } else {
                regular_filename(&filename)
            };
            let directory =
                if matches!(self.organization.duplicates, Duplicates::Separate) && !first {
                    format!("duplicates/{directory}")
                } else {
                    directory
                };
            let mut path = format!("{directory}/{filename}");
            if !paths.insert(path.to_lowercase()) {
                let name = Path::new(&filename);
                let (stem, suffix) = match name.extension().and_then(|s| s.to_str()) {
                    Some(extension) => (
                        name.file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or(&filename),
                        format!(".{extension}"),
                    ),
                    None => (filename.as_str(), String::new()),
                };
                path = format!("{directory}/{stem}-{}{suffix}", row.occurrence_id);
                ensure!(
                    paths.insert(path.to_lowercase()),
                    "unresolvable occurrence collision"
                );
            }
            ensure!(
                !directories.contains(&path.to_lowercase()),
                "view file conflicts with a directory"
            );
            let mut prefix = String::new();
            for component in directory.split('/') {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(component);
                ensure!(
                    !paths.contains(&prefix.to_lowercase()),
                    "view directory conflicts with a file or reserved export metadata name"
                );
                directories.insert(prefix.to_lowercase());
            }
            ensure!(path.len() <= 2048, "output path exceeds 2048 bytes");
            result.push(Planned {
                path,
                sha256: row.sha256.clone(),
                occurrence_id: row.occurrence_id.clone(),
            });
        }
        Ok(result)
    }
}
