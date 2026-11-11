//! TOML validation, CLI override precedence, and bounded or unlimited resource settings.

use std::process::Command;
/// Run ingest with a temporary configuration file.
fn ingest(config: &str, args: &[&str]) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config).unwrap();
    Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .args(["ingest", "--config"])
        .arg(path)
        .args(args)
        .output()
        .unwrap()
}
#[test]
/// Ensure unknown and unsafe configuration values are rejected.
fn rejects_unknown_fields_and_unsafe_security_settings() {
    for config in [
        "workres = 2",
        "[security]\nmode = 'public'",
        "[security]\nallow_automatic_unsealing = true",
        "[security]\nrestrict_directories = false",
        "[limits]\nmax_entry_bytes = 0",
    ] {
        let out = ingest(config, &[]);
        assert!(!out.status.success(), "accepted {config}");
        assert!(
            !String::from_utf8_lossy(&out.stderr).contains("not implemented"),
            "configuration was not validated: {config}"
        );
    }
}
#[test]
/// Ensure explicit worker flags override configuration values.
fn cli_workers_override_config() {
    let out = ingest("workers = 0", &["--workers", "2"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("workers must"), "{err}");
}

#[test]
fn extraction_limits_accept_readable_sizes_and_legacy_bytes() {
    let config: bfsort::app::config::Config = toml::from_str("[limits]\nmax_entry_bytes = '256 MiB'\nmax_archive_bytes = '1 GiB'\nmax_input_bytes = 1073741824").unwrap();
    config.validate().unwrap();
    assert_eq!(config.limits.max_entry_bytes, Some(268435456));
    assert_eq!(config.limits.max_archive_bytes, Some(1073741824));
    assert_eq!(config.limits.max_input_bytes, Some(1073741824));
    for value in [
        "'0 MB'",
        "'-1 MB'",
        "'1.5 MB'",
        "'18446744073709551615 GB'",
        "-1",
        "1.5",
    ] {
        assert!(
            toml::from_str::<bfsort::app::config::Config>(&format!(
                "[limits]\nmax_entry_bytes = {value}"
            ))
            .is_err()
        );
    }
    let example: bfsort::app::config::Config =
        toml::from_str(include_str!("../../examples/config.example.toml")).unwrap();
    example.validate().unwrap();
}

#[test]
fn readable_units_and_numeric_fallback_are_shared() {
    let config: bfsort::app::config::Config = toml::from_str("[source]\nmax_page_size = 5000000\n[download]\nmax_file_size = 1000\nmax_total_size = '2 MiB'\nmax_staging_size = 3000000\nmax_speed = 2000000").unwrap();
    config.download.as_ref().unwrap().validate().unwrap();
    assert_eq!(config.download.unwrap().speed().unwrap(), Some(2_000_000));
    let matcher: bfsort::organization::rules::Matcher =
        toml::from_str("min_size = '1 KB'\nmax_size = '2 MiB'").unwrap();
    assert_eq!(matcher.min_size, Some(1000));
    assert_eq!(matcher.max_size, Some(2_097_152));
    for value in ["'2 MB/s'", "'2 MiB/s'"] {
        let config: bfsort::collection::acquisition::DownloadConfig =
            toml::from_str(&format!("max_speed = {value}")).unwrap();
        assert!(config.speed().unwrap().is_some());
    }
}

#[test]
fn resource_limits_accept_explicit_unlimited() {
    let config: bfsort::app::config::Config = toml::from_str("[limits]\nmax_entry_bytes = 'unlimited'\nmax_entries = 'unlimited'\n[source]\nmax_page_size = 'unlimited'\n[download]\nmax_files = 'unlimited'\nmax_file_size = 'unlimited'\ntimeout_seconds = 'unlimited'").unwrap();
    config.validate().unwrap();
}

#[test]
fn omitted_budgets_and_deadlines_are_unlimited() {
    let config = bfsort::app::config::Config::default();
    assert!(config.limits.max_entry_bytes.is_none());
    assert!(config.limits.max_entries.is_none());
    let download = bfsort::collection::acquisition::DownloadConfig::default();
    assert!(download.timeout_seconds.is_none());
    assert!(download.max_file_size.is_none());
    for field in [
        "max_files",
        "max_requests",
        "timeout_seconds",
        "max_file_size",
        "max_total_size",
        "max_staging_size",
    ] {
        assert!(
            toml::from_str::<bfsort::collection::acquisition::DownloadConfig>(&format!(
                "{field} = 0"
            ))
            .is_err(),
            "{field}"
        );
    }
}

#[test]
fn cli_grouping_overrides_config_and_configured_resume_is_respected() {
    use clap::Parser;
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("config.toml");
    std::fs::write(&p, "rules='custom.toml'\nresume=true\n").unwrap();
    let cli = bfsort::app::cli::Cli::parse_from([
        "bfsort",
        "ingest",
        "input",
        "-c",
        p.to_str().unwrap(),
        "--preset",
        "by-format",
    ]);
    let bfsort::app::cli::Command::Ingest(args) = cli.command else {
        unreachable!()
    };
    let config = bfsort::app::config::Config::for_ingest(&args).unwrap();
    assert!(config.rules.is_none());
    assert_eq!(
        config.preset,
        Some(bfsort::organization::rules::Preset::ByFormat)
    );
    assert!(config.resume);
    std::fs::write(&p, "preset='by-extension'\n").unwrap();
    let cli = bfsort::app::cli::Cli::parse_from([
        "bfsort",
        "ingest",
        "input",
        "-c",
        p.to_str().unwrap(),
        "--rules",
        "custom.toml",
    ]);
    let bfsort::app::cli::Command::Ingest(args) = cli.command else {
        unreachable!()
    };
    let config = bfsort::app::config::Config::for_ingest(&args).unwrap();
    assert!(config.preset.is_none());
}

#[test]
fn zero_is_a_valid_rule_bound_but_not_a_resource_budget() {
    let rule: bfsort::organization::rules::Matcher =
        toml::from_str("min_size=0\nmax_size=0").unwrap();
    assert_eq!(rule.min_size, Some(0));
    assert_eq!(rule.max_size, Some(0));
    assert!(toml::from_str::<bfsort::app::config::Config>("[limits]\nmax_entry_bytes=0").is_err());
}
