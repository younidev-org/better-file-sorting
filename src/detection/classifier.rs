//! Reads content MIME types from Linux file(1) and supplies optional BFSORT aliases.

use serde::{Deserialize, Serialize};
use std::io::Seek;

include!(concat!(env!("OUT_DIR"), "/formats.rs"));

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    NotEvaluated,
    Unknown,
    Ambiguous,
    Executable,
    Document,
    Script,
    Text,
    Archive,
    Package,
    Image,
    Database,
}

impl Family {
    /// Return the identifier used in configuration and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotEvaluated => "not_evaluated",
            Self::Unknown => "unknown",
            Self::Ambiguous => "ambiguous",
            Self::Executable => "executable",
            Self::Document => "document",
            Self::Script => "script",
            Self::Text => "text",
            Self::Archive => "archive",
            Self::Package => "package",
            Self::Image => "image",
            Self::Database => "database",
        }
    }
}

#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
}
impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}
pub const FILE_DETECTOR_VERSION: &str = "linux-file-1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detection {
    pub detected_family: Family,
    pub detected_format: Format,
    pub mime_type: Option<String>,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
    pub alternatives: Vec<Format>,
    pub detector_version: String,
}
impl Default for Detection {
    fn default() -> Self {
        Self {
            detected_family: Family::NotEvaluated,
            detected_format: Format::NotEvaluated,
            mime_type: None,
            confidence: Confidence::Unknown,
            evidence: vec![],
            alternatives: vec![],
            detector_version: "not_evaluated".into(),
        }
    }
}
impl Detection {
    /// Display the registered alias or the MIME type reported by file(1).
    pub fn format_label(&self) -> &str {
        match (self.mime_type.as_deref(), self.detected_format) {
            (Some("application/octet-stream" | "application/x-empty" | "inode/x-empty"), _) => {
                "undetected"
            }
            (Some(mime), Format::Unknown | Format::NotEvaluated | Format::Ambiguous) => mime,
            (None, Format::Unknown | Format::NotEvaluated) => "undetected",
            (_, format) => format.as_str(),
        }
    }
}

/// Check the two MIME tokens accepted in classification output and filters.
pub(crate) fn valid_mime_type(value: &str) -> bool {
    value.split_once('/').is_some_and(|(kind, subtype)| {
        [kind, subtype].into_iter().all(|part| {
            part.starts_with(|c: char| c.is_ascii_alphanumeric())
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b))
        })
    })
}

/// Classify a staged or stored file with Linux file(1), using its open descriptor.
pub fn detect_file(file: &mut std::fs::File) -> anyhow::Result<Detection> {
    use anyhow::{Context, ensure};
    use std::process::{Command, Stdio};

    file.rewind()?;
    let output = Command::new("file")
        .args(["--brief", "--mime-type", "-"])
        .env("LC_ALL", "C")
        .env_remove("MAGIC")
        .stdin(Stdio::from(file.try_clone()?))
        .output()
        .context("cannot run the Linux file command")?;
    file.rewind()?;
    ensure!(output.status.success(), "Linux file command failed");
    let mime = std::str::from_utf8(&output.stdout)?.trim();
    ensure!(
        valid_mime_type(mime),
        "Linux file command returned an invalid MIME type"
    );
    let format = match mime {
        "application/x-executable"
        | "application/x-pie-executable"
        | "application/x-sharedlib"
        | "application/x-object" => Format::Elf,
        "application/x-dosexec" | "application/x-msdownload" => Format::Pe,
        "application/x-rar" | "application/x-rar-compressed" => Format::Rar,
        "application/x-gzip" => Format::Gzip,
        "application/x-sqlite3" => Format::Sqlite,
        "text/xml" => Format::Xml,
        "inode/x-empty" | "application/x-empty" => Format::Unknown,
        _ => Format::ALL
            .iter()
            .copied()
            .find(|format| format.metadata().1 == Some(mime))
            .unwrap_or(Format::Unknown),
    };
    let confidence = if format == Format::Unknown {
        Confidence::Unknown
    } else {
        Confidence::High
    };
    Ok(Detection {
        detected_family: format.metadata().0,
        detected_format: format,
        mime_type: Some(mime.to_owned()),
        confidence,
        evidence: vec!["linux_file_mime".into()],
        alternatives: vec![],
        detector_version: FILE_DETECTOR_VERSION.into(),
    })
}

/// Legacy category retained for organization rules and occurrence validation.
pub(crate) fn file_category(format: Format) -> &'static str {
    match format {
        Format::Pe | Format::Elf | Format::Macho | Format::Pdf | Format::Zip | Format::Text => {
            format.as_str()
        }
        Format::Unknown | Format::NotEvaluated | Format::Ambiguous => "unknown",
        _ => "other",
    }
}
