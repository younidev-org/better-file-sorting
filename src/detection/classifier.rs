//! Identifies supported file families from a bounded content prefix.
//! Classification is deliberately shallow: signatures and text heuristics provide
//! organization metadata without executing files or trusting filename extensions.
//! Unknown content remains eligible for storage under the fallback classification.

/// Classify content from a bounded prefix without opening or executing it.
pub fn classify(prefix: &[u8]) -> &'static str {
    if prefix.starts_with(b"\x7fELF") {
        return "elf";
    }
    if prefix.starts_with(b"%PDF-") {
        return "pdf";
    }
    if prefix.starts_with(b"PK\x03\x04") || prefix.starts_with(b"PK\x05\x06") {
        return "zip";
    }
    if prefix.len() >= 4
        && matches!(
            &prefix[..4],
            b"\xfe\xed\xfa\xce" | b"\xce\xfa\xed\xfe" | b"\xfe\xed\xfa\xcf" | b"\xcf\xfa\xed\xfe"
        )
    {
        return "macho";
    }
    if let Some(kind) = infer::get(prefix) {
        return match kind.extension() {
            "exe" => "pe",
            "mach" => "macho",
            _ => "other",
        };
    }
    if !prefix.is_empty()
        && std::str::from_utf8(prefix).is_ok_and(|s| {
            s.chars()
                .all(|c| !c.is_control() || matches!(c, '\t' | '\r' | '\n'))
        })
    {
        "text"
    } else {
        "unknown"
    }
}

use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};

macro_rules! identifiers {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        pub enum $name { $(#[serde(rename = $value)] $variant),+ }
        impl $name {
            pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $value),+ } }
        }
    };
}
identifiers!(Format {
    NotEvaluated => "not_evaluated", Unknown => "unknown", Ambiguous => "ambiguous",
    Pe => "pe", Elf => "elf", Macho => "macho", Pdf => "pdf", Rtf => "rtf", Cfb => "cfb",
    Docx => "docx", Xlsx => "xlsx", Pptx => "pptx", Javascript => "javascript",
    Powershell => "powershell", Python => "python", Shell => "shell", Batch => "batch",
    Html => "html", Xml => "xml", Json => "json", Text => "text", Zip => "zip",
    Rar => "rar", SevenZip => "7z", Tar => "tar", Gzip => "gzip", Bzip2 => "bzip2", Xz => "xz",
    Jar => "jar", Apk => "apk", Png => "png", Jpeg => "jpeg", Gif => "gif", Webp => "webp",
    Bmp => "bmp", Tiff => "tiff", Sqlite => "sqlite", Wasm => "wasm", Dex => "dex", JavaClass => "java_class", Cab => "cab", Zstd => "zstd", Lz4 => "lz4", Ar => "ar", Swf => "swf", Lnk => "lnk", Doc => "doc", Xls => "xls", Ppt => "ppt", Msi => "msi"
});
identifiers!(Family {
    NotEvaluated => "not_evaluated", Unknown => "unknown", Ambiguous => "ambiguous",
    Executable => "executable", Document => "document", Script => "script", Text => "text",
    Archive => "archive", Package => "package", Image => "image", Database => "database"
});
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
pub const DETECTOR_VERSION: &str = "bfs-2";
pub const PREFIX_LIMIT: usize = 8192;
const ZIP_DIRECTORY_LIMIT: usize = 1024 * 1024;
const ZIP_ENTRY_LIMIT: usize = 4096;

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
    pub(super) fn new(format: Format, confidence: Confidence, evidence: &str) -> Self {
        use Format::*;
        let (family, mime) = match format {
            Dex => (Family::Executable, "application/vnd.android.dex"),
            JavaClass => (Family::Executable, "application/java-vm"),
            Cab => (Family::Archive, "application/vnd.ms-cab-compressed"),
            Zstd => (Family::Archive, "application/zstd"),
            Lz4 => (Family::Archive, "application/x-lz4"),
            Ar => (Family::Archive, "application/x-archive"),
            Swf => (Family::Document, "application/x-shockwave-flash"),
            Lnk => (Family::Document, "application/x-ms-shortcut"),
            Doc => (Family::Document, "application/msword"),
            Xls => (Family::Document, "application/vnd.ms-excel"),
            Ppt => (Family::Document, "application/vnd.ms-powerpoint"),
            Msi => (Family::Package, "application/x-msi"),
            Pe => (
                Family::Executable,
                "application/vnd.microsoft.portable-executable",
            ),
            Elf => (Family::Executable, "application/x-elf"),
            Macho => (Family::Executable, "application/x-mach-binary"),
            Wasm => (Family::Executable, "application/wasm"),
            Pdf => (Family::Document, "application/pdf"),
            Rtf => (Family::Document, "application/rtf"),
            Cfb => (Family::Document, "application/x-ole-storage"),
            Docx => (
                Family::Document,
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            Xlsx => (
                Family::Document,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
            Pptx => (
                Family::Document,
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ),
            Javascript => (Family::Script, "text/javascript"),
            Powershell => (Family::Script, "text/x-powershell"),
            Python => (Family::Script, "text/x-python"),
            Shell => (Family::Script, "text/x-shellscript"),
            Batch => (Family::Script, "application/x-bat"),
            Html => (Family::Document, "text/html"),
            Xml => (Family::Document, "application/xml"),
            Json => (Family::Text, "application/json"),
            Text => (Family::Text, "text/plain"),
            Zip => (Family::Archive, "application/zip"),
            Rar => (Family::Archive, "application/vnd.rar"),
            SevenZip => (Family::Archive, "application/x-7z-compressed"),
            Tar => (Family::Archive, "application/x-tar"),
            Gzip => (Family::Archive, "application/gzip"),
            Bzip2 => (Family::Archive, "application/x-bzip2"),
            Xz => (Family::Archive, "application/x-xz"),
            Jar => (Family::Package, "application/java-archive"),
            Apk => (Family::Package, "application/vnd.android.package-archive"),
            Png => (Family::Image, "image/png"),
            Jpeg => (Family::Image, "image/jpeg"),
            Gif => (Family::Image, "image/gif"),
            Webp => (Family::Image, "image/webp"),
            Bmp => (Family::Image, "image/bmp"),
            Tiff => (Family::Image, "image/tiff"),
            Sqlite => (Family::Database, "application/vnd.sqlite3"),
            Unknown | NotEvaluated => (Family::Unknown, ""),
            Ambiguous => (Family::Ambiguous, ""),
        };
        Self {
            detected_family: family,
            detected_format: format,
            mime_type: (!mime.is_empty()).then(|| mime.into()),
            confidence,
            evidence: vec![evidence.into()],
            alternatives: vec![],
            detector_version: DETECTOR_VERSION.into(),
        }
    }
}
fn u16le(b: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32le(b: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn pe_header(b: &[u8]) -> bool {
    if !b.starts_with(b"MZ") {
        return false;
    }
    let Some(offset) = u32le(b, 60).map(|n| n as usize) else {
        return false;
    };
    if offset < 64 || offset > b.len().saturating_sub(26) {
        return false;
    }
    let optional = u16le(b, offset + 20).unwrap_or(0) as usize;
    b.get(offset..offset + 4) == Some(b"PE\0\0")
        && u16le(b, offset + 4).is_some_and(|n| n != 0)
        && u16le(b, offset + 6).is_some_and(|n| (1..=96).contains(&n))
        && optional >= 96
        && offset + 24 + optional <= b.len()
        && matches!(u16le(b, offset + 24), Some(0x10b | 0x20b))
}
fn elf_header(b: &[u8]) -> bool {
    if !b.starts_with(b"\x7fELF")
        || !matches!(b.get(4), Some(1 | 2))
        || !matches!(b.get(5), Some(1 | 2))
        || b.get(6) != Some(&1)
    {
        return false;
    }
    let (size, size_offset) = if b[4] == 2 { (64, 52) } else { (52, 40) };
    if b.len() < size {
        return false;
    }
    let field = |offset| {
        let raw: [u8; 2] = b[offset..offset + 2].try_into().expect("bounded header");
        if b[5] == 1 {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        }
    };
    let version = if b[5] == 1 {
        [1, 0, 0, 0]
    } else {
        [0, 0, 0, 1]
    };
    (matches!(field(16), 1..=4 | 0xfe00..=0xffff))
        && field(18) != 0
        && field(size_offset) as usize == size
        && b[20..24] == version
}
fn macho_header(b: &[u8]) -> bool {
    let Some(magic) = b.get(..4) else {
        return false;
    };
    let (little, size) = match magic {
        b"\xfe\xed\xfa\xce" => (false, 28),
        b"\xce\xfa\xed\xfe" => (true, 28),
        b"\xfe\xed\xfa\xcf" => (false, 32),
        b"\xcf\xfa\xed\xfe" => (true, 32),
        _ => return false,
    };
    if b.len() < size {
        return false;
    }
    let field = |offset| {
        let raw: [u8; 4] = b[offset..offset + 4].try_into().expect("bounded header");
        if little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        }
    };
    field(4) != 0 && (1..=12).contains(&field(12)) && field(16) <= field(20) / 8
}
fn bmp_header(b: &[u8]) -> bool {
    b.len() >= 54
        && b[6..10] == [0; 4]
        && u32le(b, 2).is_some_and(|n| n >= 54)
        && u32le(b, 10).is_some_and(|n| n >= 54)
        && matches!(u32le(b, 14), Some(40 | 52 | 56 | 108 | 124))
        && u32le(b, 18).is_some_and(|n| n > 0 && n <= i32::MAX as u32)
        && u32le(b, 22).is_some_and(|n| n != 0 && n != 0x80000000)
        && u16le(b, 26) == Some(1)
        && matches!(u16le(b, 28), Some(1 | 4 | 8 | 16 | 24 | 32))
}
fn pdf_header(b: &[u8]) -> bool {
    b[..b.len().min(1024)].windows(8).enumerate().any(|(i, w)| {
        (i == 0 || matches!(b[i - 1], b'\n' | b'\r' | b' '))
            && w.starts_with(b"%PDF-")
            && matches!(w[5], b'1' | b'2')
            && w[6] == b'.'
            && w[7].is_ascii_digit()
    })
}

/// Identify content using at most the existing 8 KiB prefix. Filenames are never evidence.
pub fn detect(bytes: &[u8]) -> Detection {
    detect_bounded(bytes, None)
}

fn detect_bounded(bytes: &[u8], length: Option<u64>) -> Detection {
    use Format::*;
    let b = &bytes[..bytes.len().min(PREFIX_LIMIT)];
    let mut candidates = super::headers::candidates(b, length);
    if pe_header(b) {
        candidates.push(Pe);
    }
    if elf_header(b) {
        candidates.push(Elf);
    }
    if macho_header(b) {
        candidates.push(Macho);
    }
    if pdf_header(b) {
        candidates.push(Pdf);
    }
    if b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06") {
        candidates.push(Zip);
    }
    let signatures: &[(Format, &[u8], usize)] = &[
        (Rtf, b"{\\rtf", 7),
        (Cfb, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 512),
        (Rar, b"Rar!\x1a\x07\x00", 14),
        (Rar, b"Rar!\x1a\x07\x01\x00", 16),
        (SevenZip, b"7z\xbc\xaf\x27\x1c", 32),
        (Gzip, b"\x1f\x8b\x08", 10),
        (Bzip2, b"BZh", 10),
        (Xz, b"\xfd7zXZ\0", 12),
        (Png, b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR", 16),
        (Jpeg, b"\xff\xd8\xff", 10),
        (Gif, b"GIF87a", 13),
        (Gif, b"GIF89a", 13),
        (Bmp, b"BM", 54),
        (Tiff, b"II\x2a\0", 8),
        (Tiff, b"MM\0\x2a", 8),
        (Sqlite, b"SQLite format 3\0", 16),
        (Wasm, b"\0asm\x01\0\0\0", 8),
    ];
    for (format, magic, minimum) in signatures {
        if b.len() >= *minimum && b.starts_with(magic) {
            if *format == Bzip2 && !matches!(b.get(3), Some(b'1'..=b'9')) {
                continue;
            }
            if *format == Gzip && b[3] & 0xe0 != 0 {
                continue;
            }
            if *format == Bmp && !bmp_header(b) {
                continue;
            }
            candidates.push(*format);
        }
    }
    if b.len() >= 12 && b.starts_with(b"RIFF") && b.get(8..12) == Some(b"WEBP") {
        candidates.push(Webp);
    }
    if b.len() >= 512
        && b.get(257..263)
            .is_some_and(|s| s == b"ustar\0" || s == b"ustar ")
    {
        let sum: u64 = b[..512]
            .iter()
            .enumerate()
            .map(|(i, v)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *v as u64
                }
            })
            .sum();
        if std::str::from_utf8(&b[148..156])
            .ok()
            .and_then(|s| u64::from_str_radix(s.trim_matches(['\0', ' ']), 8).ok())
            == Some(sum)
        {
            candidates.push(Tar);
        }
    }
    if candidates.len() > 1 {
        let mut d = Detection::new(Ambiguous, Confidence::Medium, "conflicting_headers");
        d.alternatives = candidates;
        return d;
    }
    if let Some(format) = candidates.first() {
        if *format == Zip {
            return zip_detection(&mut std::io::Cursor::new(b))
                .unwrap_or_else(|| Detection::new(Zip, Confidence::Medium, "zip_prefix_only"));
        }
        return Detection::new(*format, Confidence::High, "signature_and_bounded_header");
    }
    if b.starts_with(&[0xff, 0xfe]) || b.starts_with(&[0xfe, 0xff]) {
        let little = b[0] == 0xff;
        let raw = &b[2..];
        if raw.len().is_multiple_of(2) {
            let words = raw.as_chunks::<2>().0.iter().map(|p| {
                if little {
                    u16::from_le_bytes([p[0], p[1]])
                } else {
                    u16::from_be_bytes([p[0], p[1]])
                }
            });
            if let Ok(text) = String::from_utf16(&words.collect::<Vec<_>>()) {
                let mut detection = detect(text.as_bytes());
                if matches!(
                    detection.detected_family,
                    Family::Text | Family::Script | Family::Document
                ) {
                    detection.evidence.push("utf16_bom".into());
                    return detection;
                }
            }
        }
    }
    if let Ok(text) = std::str::from_utf8(b)
        && !text.is_empty()
        && text
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
    {
        if let Some(line) = text.strip_prefix("#!").and_then(|s| s.lines().next()) {
            let mut words = line.split_whitespace();
            let executable = words.next().unwrap_or("");
            let interpreter = if executable.rsplit('/').next() == Some("env") {
                let next = words.next().unwrap_or("");
                if next == "-S" {
                    words.next().unwrap_or("")
                } else {
                    next
                }
            } else {
                executable.rsplit('/').next().unwrap_or("")
            };
            let format = match interpreter {
                "python" | "python2" | "python3" => Some(Python),
                "sh" | "bash" | "dash" | "zsh" | "ksh" => Some(Shell),
                "node" | "nodejs" => Some(Javascript),
                "pwsh" | "powershell" => Some(Powershell),
                _ => None,
            };
            if let Some(format) = format {
                return Detection::new(format, Confidence::High, "shebang_interpreter");
            }
        }
        let text = text.trim_start_matches('\u{feff}').trim_start();
        let lower = text.to_ascii_lowercase();
        if lower.starts_with("@echo off") && lower[9..].starts_with(['\r', '\n']) {
            return Detection::new(Batch, Confidence::Medium, "batch_preamble");
        }
        if lower.starts_with("<!doctype html") || lower.starts_with("<html") {
            return Detection::new(Html, Confidence::Medium, "html_preamble");
        }
        if text.starts_with("<?xml ") && text.contains("?>") {
            return Detection::new(Xml, Confidence::Medium, "xml_declaration");
        }
        if text.starts_with(['{', '[']) && serde_json::from_str::<serde_json::Value>(text).is_ok() {
            return Detection::new(Json, Confidence::Medium, "complete_json");
        }
        return Detection::new(Text, Confidence::Low, "printable_utf8");
    }
    Detection::new(Unknown, Confidence::Unknown, "insufficient_evidence")
}

/// Inspect only bounded ZIP directory metadata through the already-open staging handle.
/// ZIP64, multi-disk, oversized or malformed directories conservatively remain ZIP.
fn zip_detection<R: Read + Seek>(reader: &mut R) -> Option<Detection> {
    let size = reader.seek(SeekFrom::End(0)).ok()?;
    let tail_size = size.min(65557) as usize;
    reader.seek(SeekFrom::End(-(tail_size as i64))).ok()?;
    let mut tail = vec![0; tail_size];
    reader.read_exact(&mut tail).ok()?;
    let eocd = (0..tail.len().saturating_sub(21)).rev().find(|i| {
        tail.get(*i..*i + 4) == Some(b"PK\x05\x06")
            && u16le(&tail, i + 20).is_some_and(|n| i + 22 + n as usize == tail.len())
    })?;
    if u16le(&tail, eocd + 4)? != 0 || u16le(&tail, eocd + 6)? != 0 {
        return None;
    }
    let entries = u16le(&tail, eocd + 10)? as usize;
    if entries > ZIP_ENTRY_LIMIT || u16le(&tail, eocd + 8)? as usize != entries {
        return None;
    }
    let length = u32le(&tail, eocd + 12)? as usize;
    let offset = u32le(&tail, eocd + 16)? as u64;
    if length > ZIP_DIRECTORY_LIMIT
        || offset + length as u64 != size - tail_size as u64 + eocd as u64
    {
        return None;
    }
    reader.seek(SeekFrom::Start(offset)).ok()?;
    let mut directory = vec![0; length];
    reader.read_exact(&mut directory).ok()?;
    let mut names = std::collections::BTreeSet::new();
    let mut pos = 0usize;
    for _ in 0..entries {
        if directory.get(pos..pos.checked_add(4)?) != Some(b"PK\x01\x02") {
            return None;
        }
        let name_len = u16le(&directory, pos + 28)? as usize;
        if name_len > 4096 {
            return None;
        }
        let extra = u16le(&directory, pos + 30)? as usize;
        let comment = u16le(&directory, pos + 32)? as usize;
        let start = pos.checked_add(46)?;
        let end = start.checked_add(name_len)?;
        let name = directory.get(start..end)?;
        names.insert(name.to_vec());
        pos = end.checked_add(extra)?.checked_add(comment)?;
        if pos > directory.len() {
            return None;
        }
    }
    if pos != directory.len() {
        return None;
    }
    let has = |name: &[u8]| names.contains(name);
    let mut formats = vec![];
    use Format::*;
    if has(b"[Content_Types].xml") {
        for (marker, format) in [
            (b"word/document.xml".as_slice(), Docx),
            (b"xl/workbook.xml", Xlsx),
            (b"ppt/presentation.xml", Pptx),
        ] {
            if has(marker) {
                formats.push(format);
            }
        }
    }
    if has(b"AndroidManifest.xml") && (has(b"classes.dex") || has(b"resources.arsc")) {
        formats.push(Apk);
    }
    // APKs commonly carry a JAR manifest too; that relationship is not a conflict.
    if has(b"META-INF/MANIFEST.MF") && !formats.contains(&Apk) {
        formats.push(Jar);
    }
    let mut d = Detection::new(
        if formats.len() > 1 {
            Ambiguous
        } else {
            formats.first().copied().unwrap_or(Zip)
        },
        if formats.len() > 1 {
            Confidence::Medium
        } else {
            Confidence::High
        },
        "bounded_zip_directory",
    );
    if formats.len() > 1 {
        d.alternatives = formats;
    }
    Some(d)
}
pub fn detect_reader<R: Read + Seek>(prefix: &[u8], reader: &mut R) -> Detection {
    let length = reader.seek(SeekFrom::End(0)).ok();
    let detection = detect_bounded(prefix, length);
    if detection.detected_format == Format::Zip {
        zip_detection(reader).unwrap_or(detection)
    } else if detection.detected_format == Format::Cfb {
        super::compound::detect(reader).unwrap_or(detection)
    } else {
        detection
    }
}
