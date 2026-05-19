default:
    @just --list

install:
    cargo install --path . --locked

build:
    cargo build --workspace

test:
    cargo test --workspace

lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings

fix:
    cargo fmt --all
    cargo clippy --workspace --all-targets --fix --allow-dirty -- -D warnings

scan path="tests/fixtures/skills/clean":
    cargo run -- scan {{path}}

audit:
    cargo deny check
