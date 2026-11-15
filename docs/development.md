# Development

[Documentation](README.md) · [Reliability and validation](validation.md)

## Build

Linux is the supported runtime platform. Build from the repository root:

```sh
cargo build --release --locked --bin bfsort
target/release/bfsort --version
```

## Check changes

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
```

Integration tests use synthetic fixtures and temporary repositories. HTTP tests start local servers and require loopback access.
