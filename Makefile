.PHONY: all build release test lint fmt clippy audit install hook selfscan clean

all: lint test

build:
	cargo build

release:
	cargo build --release

test:
	cargo test --all

lint: fmt clippy

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

audit:
	cargo audit --deny warnings

install:
	cargo install --path .

## hook: install the pre-commit hook in this repository
hook: install
	secret-scan --install-hook

## selfscan: scan this repository, history included
selfscan:
	cargo run -- --no-color --show-suppressed .
	cargo run -- --no-color --history .

clean:
	cargo clean
