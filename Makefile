# Checks this crate. Run from the repository root:
#
#   make check   formatting, lints (the live suites included), the unit and
#                integration tests, the README snippets and the docs build
#   make live    the acceptance suites against a real Celeris stack, from .env
#
# Releasing is `cargo publish`, after the client version that this crate needs
# is published. Nothing here does it.

.PHONY: check live

check:
	cargo fmt --check
	cargo clippy --all-targets --locked -- -D warnings
	cargo clippy --test live --locked -- -D warnings
	cargo test --locked
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked

live:
	cargo test --locked --test live -- --test-threads=1
