// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Download policy selection, byte settings, inventory defaults, and staging validation.

use bfsort::collection::acquisition::parse_bytes;

#[test]
fn readable_sizes() {
    assert_eq!(parse_bytes("1 GB").unwrap(), 1_000_000_000);
    assert_eq!(parse_bytes("1 GiB").unwrap(), 1_073_741_824);
    for invalid in ["-1 MB", "1.5 MB", "12", "0 B", "18446744073709551615 TB"] {
        assert!(parse_bytes(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn policies_exclude_before_include_and_sort_names() {
    use bfsort::collection::acquisition::*;
    let config: DownloadConfig = toml::from_str(
        r#"
        order_by = "name"
        [[policies]]
        name_contains = "linux"
        action = "include"
        [[policies]]
        name_contains = "old"
        action = "exclude"
    "#,
    )
    .unwrap();
    let inventory = Inventory {
        version: 2,
        candidates: ["Linux Z", "Windows", "OLD Linux", "linux A"]
            .into_iter()
            .map(|title| Candidate {
                source_id: title.into(),
                url: String::new(),
                name: title.into(),
            })
            .collect(),
    };
    let selected = select_candidates(&inventory, &config).unwrap();
    assert_eq!(
        selected.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        ["linux A", "Linux Z"]
    );
}

#[test]
fn limits_and_directory_validation() {
    use bfsort::collection::acquisition::DownloadConfig;
    for setting in [
        "max_speed = '0 MB/s'",
        "max_speed = '2 MB'",
        "max_requests = 0",
        "directory = '../escape'",
        "concurrency = 0",
    ] {
        assert!(
            toml::from_str::<DownloadConfig>(setting)
                .map_err(anyhow::Error::from)
                .and_then(|config| config.validate())
                .is_err()
        );
    }
    let config: DownloadConfig =
        toml::from_str("max_speed = '2 MB/s'\nmin_request_interval_ms = 0").unwrap();
    assert_eq!(config.speed().unwrap(), Some(2_000_000));
    assert_eq!(DownloadConfig::default().speed().unwrap(), None);
}

#[test]
fn existing_staging_directory_must_be_private() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("payloads");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(bfsort::collection::acquisition::private_tree(&path).is_err());
}

#[test]
fn download_defaults_do_not_impose_transfer_caps() {
    use bfsort::collection::acquisition::*;
    let config = DownloadConfig::default();
    config.validate().unwrap();
    assert_eq!(config.max_files, None);
    for size in [
        &config.max_file_size,
        &config.max_total_size,
        &config.max_staging_size,
    ] {
        assert_eq!(*size, None);
    }
    assert_eq!(config.speed().unwrap(), None);
    assert_eq!(config.min_request_interval_ms, 0);
    assert_eq!(config.max_requests, None);
}

#[test]
fn default_inventory_uses_json() {
    use bfsort::collection::acquisition::DownloadConfig;
    assert_eq!(
        DownloadConfig::default().inventory.file_name().unwrap(),
        "inventory.json"
    );
}
