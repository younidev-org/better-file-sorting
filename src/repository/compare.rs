//! Compare effective repository metadata without reading payloads.
use super::{metadata, storage::Repository};
use crate::app::presentation::Progress;
use anyhow::Result;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
#[derive(Debug, Serialize)]
pub struct CountDifference {
    pub sha256: String,
    pub left: usize,
    pub right: usize,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub occurrence_counts: Vec<CountDifference>,
    pub detection_differences: Vec<String>,
    pub left_detector_versions: Vec<String>,
    pub right_detector_versions: Vec<String>,
}
fn compare(left: &[metadata::Occurrence], right: &[metadata::Occurrence]) -> Result<Report> {
    fn group(
        rows: &[metadata::Occurrence],
        progress: &Progress,
    ) -> Result<BTreeMap<String, (usize, BTreeSet<String>)>> {
        let mut map = BTreeMap::new();
        for row in rows {
            let entry = map
                .entry(row.sha256.clone())
                .or_insert_with(|| (0, BTreeSet::new()));
            entry.0 += 1;
            entry.1.insert(serde_json::to_string(&row.detection)?);
            progress.0.inc(1);
        }
        Ok(map)
    }
    let progress = Progress::new(Some((left.len() + right.len()) as u64), "Comparing records");
    let l = group(left, &progress)?;
    let r = group(right, &progress)?;
    let versions = |rows: &[metadata::Occurrence]| {
        rows.iter()
            .map(|x| x.detection.detector_version.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    Ok(Report {
        added: r.keys().filter(|h| !l.contains_key(*h)).cloned().collect(),
        removed: l.keys().filter(|h| !r.contains_key(*h)).cloned().collect(),
        occurrence_counts: l
            .iter()
            .filter_map(|(h, (count, _))| {
                r.get(h).filter(|x| x.0 != *count).map(|x| CountDifference {
                    sha256: h.clone(),
                    left: *count,
                    right: x.0,
                })
            })
            .collect(),
        detection_differences: l
            .iter()
            .filter_map(|(h, (_, detections))| {
                r.get(h).filter(|x| x.1 != *detections).map(|_| h.clone())
            })
            .collect(),
        left_detector_versions: versions(left),
        right_detector_versions: versions(right),
    })
}
pub fn run(left: &Path, right: &Path) -> Result<Report> {
    let loading = Progress::new(None, "Loading repositories for comparison");
    let left = left.canonicalize()?;
    let right = right.canonicalize()?;
    if left == right {
        let repo = Repository::existing(&left)?;
        let records = metadata::load(repo.root())?;
        drop(loading);
        return compare(&records, &records);
    }
    // Lock in canonical path order so reverse comparisons have the same lock order.
    let (first, second) = if left < right {
        (&left, &right)
    } else {
        (&right, &left)
    };
    let a = Repository::existing(first)?;
    let b = Repository::existing(second)?;
    let ar = metadata::load(a.root())?;
    let br = metadata::load(b.root())?;
    drop(loading);
    if left < right {
        compare(&ar, &br)
    } else {
        compare(&br, &ar)
    }
}
