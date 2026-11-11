// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Command-line contracts for help, defaults, diagnostics, and machine-readable output.

use std::process::Command;

#[test]
/// Ensure help exposes every top-level command.
fn help_lists_commands() {
    let out = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout).unwrap();
    assert!(
        help.contains("Usage: bfsort"),
        "unexpected CLI name: {help}"
    );
    for command in ["ingest", "inspect", "stats", "reorganize"] {
        assert!(help.contains(command), "missing {command}");
    }
}

#[test]
/// Ensure invalid configuration fails before creating the output path.
fn rejects_invalid_configuration_before_output_creation() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "workers = 0\n").unwrap();
    let output = dir.path().join("repo");
    let status = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .args(["ingest", "--config"])
        .arg(config)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!status.status.success());
    assert!(!output.exists());
}

#[test]
fn discover_accepts_url_without_config() {
    use clap::Parser;
    assert!(
        bfsort::app::cli::Cli::try_parse_from(["bfs", "discover", "https://example.org/"]).is_ok()
    );
    assert!(
        bfsort::app::cli::Cli::try_parse_from(["bfs", "discover", "--config", "collection.toml"])
            .is_ok()
    );
    assert!(bfsort::app::cli::Cli::try_parse_from(["bfs", "discover"]).is_ok());
    assert!(bfsort::app::cli::Cli::try_parse_from(["bfs", "download"]).is_ok());
}

#[test]
fn commands_accept_default_settings_without_config() {
    use clap::Parser;
    for command in ["download", "ingest", "inspect", "stats", "reorganize"] {
        assert!(
            bfsort::app::cli::Cli::try_parse_from(["bfs", command]).is_ok(),
            "{command}"
        );
    }
}

#[test]
fn local_default_workflow_uses_incoming_and_organized() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("incoming")).unwrap();
    let file = std::fs::File::create(temp.path().join("incoming/example.zip")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("hello.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"hello").unwrap();
    zip.finish().unwrap();
    for args in [
        vec!["inspect"],
        vec!["ingest"],
        vec!["stats"],
        vec!["reorganize", "--dry-run"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_bfsort"))
            .args(&args)
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert!(temp.path().join("organized/security.json").is_file());
    assert!(temp.path().join("incoming/example.zip").is_file());
    assert!(!temp.path().join("repository").exists());
    assert!(!temp.path().join("downloads").exists());
}

#[test]
fn reworked_workflow_flags_parse() {
    use clap::Parser;
    for args in [
        vec![
            "bfs",
            "collect",
            "https://example.org/",
            "-o",
            "collection",
            "-j",
            "2",
            "--refresh",
            "--dry-run",
        ],
        vec!["bfs", "ingest", "incoming", "-o", "organized", "--extract"],
        vec!["bfs", "--no-color", "--quiet", "--json", "ingest"],
        vec!["bfs", "config", "validate", "-c", "bfs.toml"],
    ] {
        assert!(
            bfsort::app::cli::Cli::try_parse_from(&args).is_ok(),
            "{args:?}"
        );
    }
}

#[test]
fn default_config_and_overrides_are_local() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("bfs.toml"), "workers = 0").unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_bfsort"))
            .current_dir(temp.path())
            .args(args)
            .output()
            .unwrap()
    };
    let invalid = run(&["config", "validate"]);
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("workers"));
    let missing = run(&["config", "validate", "-c", "missing.toml"]);
    assert!(String::from_utf8_lossy(&missing.stderr).contains("configuration file not found"));
    std::fs::write(temp.path().join("bfs.toml"), "workres = 1").unwrap();
    let invalid = run(&["config", "validate"]);
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("workres"));
}

#[test]
fn human_repository_errors_and_global_help_color() {
    let temp = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_bfsort"))
            .current_dir(temp.path())
            .args(args)
            .output()
            .unwrap()
    };
    let missing = run(&["stats", "collection"]);
    let error = String::from_utf8_lossy(&missing.stderr);
    assert!(
        error.contains("collection") && error.contains("security.json") && error.contains("ingest"),
        "{error}"
    );
    for args in [
        vec!["--color", "always", "stats", "--help"],
        vec!["stats", "--color", "always", "--help"],
    ] {
        assert!(run(&args).stdout.contains(&0x1b));
    }
    assert!(
        !run(&["stats", "--color", "always", "--no-color", "--help"])
            .stdout
            .contains(&0x1b)
    );
    assert!(!run(&["organize"]).status.success());
}

#[test]
fn stats_are_human_and_machine_bytes_remain_numeric() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("sample.txt"), vec![b'x'; 2048]).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_bfsort"))
            .current_dir(temp.path())
            .args(args)
            .output()
            .unwrap()
    };
    assert!(run(&["ingest", "sample.txt"]).status.success());
    let human = run(&["stats"]);
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(
        text.contains("Repository") && text.contains("Unique hashes") && text.contains("2.00 KiB"),
        "{text}"
    );
    assert!(!text.starts_with('{'));
    let machine = run(&["stats", "--json", "--color", "always"]);
    assert!(!machine.stdout.contains(&0x1b));
    let value: serde_json::Value = serde_json::from_slice(&machine.stdout).unwrap();
    assert_eq!(value["stored_bytes"], 2048);
}

#[test]
fn machine_reports_disable_both_stream_colors() {
    let temp = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_bfsort"))
            .current_dir(temp.path())
            .args(args)
            .output()
            .unwrap()
    };
    for format in ["json", "csv"] {
        let out = run(&[
            "report",
            "mismatches",
            "missing",
            "--format",
            format,
            "--color",
            "always",
        ]);
        assert!(!out.stdout.contains(&27) && !out.stderr.contains(&27));
    }
}

#[test]
fn preview_colors_labels_not_paths_and_machine_parse_errors_are_plain() {
    let t = tempfile::tempdir().unwrap();
    let input = t.path().join("note.txt");
    std::fs::write(&input, b"hello").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .args([
            "ingest",
            "--input-mode",
            "files",
            "--dry-run",
            "--color",
            "always",
        ])
        .arg(&input)
        .arg("-o")
        .arg(t.path().join("out"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        !out.stdout.starts_with(b"\x1b"),
        "path was styled as a status label"
    );
    let out = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .args([
            "report",
            "mismatches",
            "--format",
            "csv",
            "--color",
            "always",
            "--invalid-option",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!out.stderr.contains(&0x1b));
}

#[test]
fn verbose_config_reports_discovery_and_download_budgets() {
    let output = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .args([
            "config",
            "validate",
            "-c",
            "examples/bounded.toml",
            "--verbose",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Discovery:"));
    assert!(stderr.contains("Download budgets:"));
    assert!(stderr.contains("10.00 GiB"));
}

#[test]
fn quiet_suppresses_json_stdout_but_keeps_errors() {
    let out = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .args(["config", "validate", "--quiet", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    let out = Command::new(env!("CARGO_BIN_EXE_bfsort"))
        .args([
            "stats",
            "/nonexistent/bfsort-test-repo",
            "--quiet",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}
