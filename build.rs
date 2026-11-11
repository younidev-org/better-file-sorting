//! Generate typed detector identifiers and their metadata from the bundled format table.

use serde::Deserialize;
use std::{collections::BTreeSet, fmt::Write, fs, path::PathBuf};

const FORMAT_TABLE: &str = "src/detection/formats.toml";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    formats: Vec<Format>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Format {
    variant: String,
    id: String,
    family: String,
    mime: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed={FORMAT_TABLE}");
    let table: Table = toml::from_str(&fs::read_to_string(FORMAT_TABLE)?)?;
    let mut variants = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut names = String::new();
    let mut strings = String::new();
    let mut metadata = String::new();
    let mut all = String::new();

    for Format {
        variant,
        id,
        family,
        mime,
    } in table.formats
    {
        assert!(
            variant.starts_with(|c: char| c.is_ascii_uppercase())
                && variant.bytes().all(|b| b.is_ascii_alphanumeric()),
            "invalid format variant {variant:?}"
        );
        assert!(
            variants.insert(variant.clone()),
            "duplicate format variant {variant}"
        );
        assert!(
            !id.is_empty() && ids.insert(id.clone()),
            "empty or duplicate format ID {id:?}"
        );
        let family: String = family
            .split('_')
            .map(|word| {
                assert!(
                    !word.is_empty() && word.bytes().all(|b| b.is_ascii_lowercase()),
                    "invalid family {family:?} for {id}"
                );
                format!("{}{}", word[..1].to_ascii_uppercase(), &word[1..])
            })
            .collect();
        let mime = mime.map_or_else(|| "None".to_owned(), |value| format!("Some({value:?})"));
        writeln!(names, "    #[serde(rename = {id:?})]\n    {variant},")?;
        writeln!(strings, "            Self::{variant} => {id:?},")?;
        writeln!(
            metadata,
            "            Self::{variant} => (Family::{family}, {mime}),"
        )?;
        writeln!(all, "        Self::{variant},")?;
    }

    let generated = format!(
        "/// File formats recognized by the built-in detector.\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]\n\
         pub enum Format {{\n{names}}}\n\n\
         impl Format {{\n\
             #[cfg(test)]\n    const ALL: &'static [Self] = &[\n{all}    ];\n\n\
             /// Return the identifier used in configuration and reports.\n\
             pub fn as_str(self) -> &'static str {{\n        match self {{\n{strings}        }}\n    }}\n\n\
             fn metadata(self) -> (Family, Option<&'static str>) {{\n        match self {{\n{metadata}        }}\n    }}\n\
         }}\n"
    );
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    fs::write(output.join("formats.rs"), generated)?;
    Ok(())
}
