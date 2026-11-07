//! Shared selectors for stored records and freshly classified inputs.
//!
//! Stored selections use the indexed columns of the SQLite catalog. Ingestion
//! applies the same criteria to records in memory before publication.
use crate::{
    detection::{classifier::Format, mismatch::Status},
    repository::metadata::Occurrence,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// Criteria that a single occurrence must satisfy.
///
/// Values in each inclusion list are alternatives. All populated inclusion
/// criteria must match, and either exclusion list can reject a match. Size
/// bounds are inclusive. Extensions come from the original filename and
/// detected formats come from content classification.
///
/// For example, a PDF named `sample.bin` matches a PDF format filter.
///
/// ```
/// use bfsort::{detection::classifier::Format, selection::Filters};
///
/// let pdfs = Filters {
///     include_formats: vec![Format::Pdf],
///     ..Filters::default()
/// };
/// pdfs.validate()?;
/// # Ok::<(), anyhow::Error>(())
/// ```
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Filters {
    pub include_extensions: Vec<String>,
    pub exclude_extensions: Vec<String>,
    pub include_formats: Vec<Format>,
    pub exclude_formats: Vec<Format>,
    pub sha256: Option<String>,
    pub mismatch: Option<Status>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
}

#[derive(Debug, Clone, Default, clap::Args)]
pub struct Selection {
    #[arg(long, value_delimiter = ',')]
    pub include_ext: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    pub exclude_ext: Vec<String>,
    #[arg(long, value_delimiter = ',', value_parser = parse_format)]
    pub include_format: Vec<Format>,
    #[arg(long, value_delimiter = ',', value_parser = parse_format)]
    pub exclude_format: Vec<Format>,
    #[arg(long)]
    pub sha256: Option<String>,
    #[arg(long, value_enum)]
    pub mismatch: Option<Status>,
    /// Inclusive minimum size in bytes
    #[arg(long)]
    pub min_size: Option<u64>,
    /// Inclusive maximum size in bytes
    #[arg(long)]
    pub max_size: Option<u64>,
}

fn parse_format(value: &str) -> std::result::Result<Format, String> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|_| format!("unsupported detected format: {value}"))
}

impl Selection {
    /// Apply supplied CLI options over configured filters and validate the result.
    ///
    /// Each nonempty CLI list replaces the corresponding configured list.
    /// Omitted options retain their configured values.
    pub fn resolve(&self, mut base: Filters) -> Result<Filters> {
        for (cli, configured) in [
            (&self.include_ext, &mut base.include_extensions),
            (&self.exclude_ext, &mut base.exclude_extensions),
        ] {
            if !cli.is_empty() {
                configured.clone_from(cli);
            }
        }
        if !self.include_format.is_empty() {
            base.include_formats.clone_from(&self.include_format);
        }
        if !self.exclude_format.is_empty() {
            base.exclude_formats.clone_from(&self.exclude_format);
        }
        if self.sha256.is_some() {
            base.sha256.clone_from(&self.sha256);
        }
        if self.mismatch.is_some() {
            base.mismatch = self.mismatch;
        }
        if self.min_size.is_some() {
            base.min_size = self.min_size;
        }
        if self.max_size.is_some() {
            base.max_size = self.max_size;
        }
        base.validate()?;
        Ok(base)
    }
}

impl Filters {
    pub fn validate(&self) -> Result<()> {
        for extension in self
            .include_extensions
            .iter()
            .chain(&self.exclude_extensions)
        {
            let extension = extension.strip_prefix('.').unwrap_or(extension);
            ensure!(
                !extension.is_empty()
                    && !extension.chars().any(|c| c.is_whitespace()
                        || c.is_control()
                        || matches!(c, '/' | '\\' | ',' | '.')),
                "invalid extension filter"
            );
        }
        ensure!(
            self.min_size.unwrap_or(0) <= self.max_size.unwrap_or(u64::MAX),
            "minimum size exceeds maximum size"
        );
        ensure!(
            self.sha256
                .as_ref()
                .is_none_or(|h| crate::repository::storage::valid_hash(h)),
            "invalid SHA-256 filter"
        );
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.include_extensions.is_empty()
            && self.exclude_extensions.is_empty()
            && self.include_formats.is_empty()
            && self.exclude_formats.is_empty()
            && self.sha256.is_none()
            && self.mismatch.is_none()
            && self.min_size.is_none()
            && self.max_size.is_none()
    }

    /// Test the record's saved classification, original extension, hash, and size.
    ///
    /// This predicate evaluates metadata fields only. Repository selection also
    /// applies catalog visibility rules for structural ancestors and removals.
    pub fn matches(&self, row: &Occurrence) -> bool {
        self.matches_fields(
            &row.original_extension,
            &row.detection,
            &row.sha256,
            row.size,
            row.mismatch.status,
        )
    }

    pub fn matches_file(
        &self,
        name: &str,
        detection: &crate::detection::classifier::Detection,
        sha: &str,
        size: u64,
    ) -> bool {
        let basename = name.rsplit(['/', '\\']).next().unwrap_or("");
        let extension = std::path::Path::new(basename)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        self.matches_fields(
            extension,
            detection,
            sha,
            size,
            crate::detection::mismatch::evaluate(name, detection).status,
        )
    }

    fn matches_fields(
        &self,
        extension: &str,
        detection: &crate::detection::classifier::Detection,
        sha: &str,
        size: u64,
        mismatch: Status,
    ) -> bool {
        let ext = crate::detection::mismatch::normalize_extension(extension);
        let extension_matches =
            |value: &String| crate::detection::mismatch::normalize_extension(value) == ext;
        (self.include_extensions.is_empty()
            || self.include_extensions.iter().any(extension_matches))
            && !self.exclude_extensions.iter().any(extension_matches)
            && (self.include_formats.is_empty()
                || self.include_formats.contains(&detection.detected_format))
            && !self.exclude_formats.contains(&detection.detected_format)
            && self.sha256.as_ref().is_none_or(|hash| hash == sha)
            && self.mismatch.is_none_or(|status| status == mismatch)
            && self.min_size.is_none_or(|min| size >= min)
            && self.max_size.is_none_or(|max| size <= max)
    }

    pub fn retain(&self, rows: &mut Vec<Occurrence>) {
        rows.retain(|r| self.matches(r));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_replaces_lists_and_exclusions_remain() {
        let selection = Selection {
            include_ext: vec![".PDF".into()],
            ..Default::default()
        };
        let filters = selection
            .resolve(Filters {
                include_extensions: vec!["txt".into()],
                exclude_extensions: vec!["exe".into()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(filters.include_extensions, [".PDF"]);
        assert_eq!(filters.exclude_extensions, ["exe"]);
        assert!(
            Filters {
                include_extensions: vec!["".into()],
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(parse_format("invalid").is_err());
    }
    #[test]
    fn file_selection_uses_name_and_detected_content_independently() {
        let detection = crate::detection::classifier::detect(b"%PDF-1.7\nfixture");
        let filters = Filters {
            include_extensions: vec![".TXT".into()],
            include_formats: vec![Format::Pdf],
            min_size: Some(3),
            ..Default::default()
        };
        assert!(filters.matches_file("folder/renamed.txt", &detection, "hash", 3));
        assert!(!filters.matches_file("folder/renamed.pdf", &detection, "hash", 3));
        assert!(!filters.matches_file("folder/renamed.txt", &detection, "hash", 2));
        let other = crate::detection::classifier::detect(b"plain prose");
        assert!(!filters.matches_file("folder/renamed.txt", &other, "hash", 3));
    }
}
