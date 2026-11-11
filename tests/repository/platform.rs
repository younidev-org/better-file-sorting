//! Platform security requirements and validation of example configurations and rules.

#[cfg(not(unix))]
#[test]
/// Ensure unsupported platforms fail closed instead of weakening storage.
fn storage_fails_closed_without_acl_backend() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("repo");
    assert!(
        bfsort::repository::storage::Repository::open(
            &root,
            bfsort::app::config::SecurityMode::Sealed
        )
        .is_err()
    );
    assert!(!root.exists());
}
#[test]
/// Ensure shipped example configuration files remain parseable.
fn example_configuration_and_rules_are_valid() {
    let config: bfsort::app::config::Config =
        toml::from_str(include_str!("../../examples/config.example.toml")).unwrap();
    config.validate().unwrap();
    bfsort::organization::rules::Rules::parse(include_str!("../../examples/rules.example.toml"))
        .unwrap();
    bfsort::organization::rules::Rules::parse(include_str!(
        "../../examples/rules.files.example.toml"
    ))
    .unwrap();
}
