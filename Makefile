.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# -- variables --------------------------------------------------------------------------------------

WARNINGS=RUSTDOCFLAGS="-D warnings"
DEBUG_ASSERTIONS=RUSTFLAGS="-C debug-assertions"
FEATURES_CONCURRENT_EXEC=--features concurrent,executable
FEATURES_LOG_TREE=--features concurrent,executable,tracing-forest
FEATURES_METAL_EXEC=--features concurrent,executable,metal
ALL_FEATURES_BUT_ASYNC=--features concurrent,executable,metal,testing,with-debug-info,internal

# -- linting --------------------------------------------------------------------------------------

.PHONY: clippy
clippy: ## Runs Clippy with configs
	cargo +nightly clippy --workspace --all-targets ${ALL_FEATURES_BUT_ASYNC} -- -D warnings


.PHONY: fix
fix: ## Runs Fix with configs
	cargo +nightly fix --allow-staged --allow-dirty --all-targets ${ALL_FEATURES_BUT_ASYNC}


.PHONY: format
format: ## Runs Format using nightly toolchain
	cargo +nightly fmt --all


.PHONY: format-check
format-check: ## Runs Format using nightly toolchain but only in check mode
	cargo +nightly fmt --all --check


.PHONY: lint
lint: format fix clippy ## Runs all linting tasks at once (Clippy, fixing, formatting)

# --- docs ----------------------------------------------------------------------------------------

.PHONY: doc
doc: ## Generates & checks documentation
	$(WARNINGS) cargo doc ${ALL_FEATURES_BUT_ASYNC} --keep-going --release

.PHONY: mdbook
mdbook: ## Generates mdbook documentation
	mdbook build docs/

# --- testing -------------------------------------------------------------------------------------

.PHONY: test
test: ## Runs all tests with the release profile
	$(DEBUG_ASSERTIONS) cargo nextest run --cargo-profile test-release --features testing

.PHONY: test-fast
test-fast: ## Runs all tests with the debug profile
	$(DEBUG_ASSERTIONS) cargo nextest run --features testing

.PHONY: test-skip-proptests
test-skip-proptests: ## Runs all tests, except property-based tests
	$(DEBUG_ASSERTIONS) cargo nextest run --features testing -E 'not test(#*proptest)'

.PHONY: test-loom
test-loom: ## Runs all loom-based tests
	RUSTFLAGS="--cfg loom" cargo nextest run --cargo-profile test-release --features testing -E 'test(#*loom)'

.PHONY: test-package
test-package: ## Tests specific package: make test-package package=miden-vm
	$(DEBUG_ASSERTIONS) cargo nextest run --cargo-profile test-release --features testing -p $(package)

# --- checking ------------------------------------------------------------------------------------

.PHONY: check
check: ## Checks all targets and features for errors without code generation
	cargo check --all-targets ${ALL_FEATURES_BUT_ASYNC}

# --- building ------------------------------------------------------------------------------------

.PHONY: build
build: ## Builds with default parameters
	cargo build --release --features concurrent

.PHONY: build-no-std
build-no-std: ## Builds without the standard library
	cargo build --no-default-features --target wasm32-unknown-unknown --workspace

# --- executable ------------------------------------------------------------------------------------

.PHONY: exec
exec: ## Builds an executable with optimized profile and features
	cargo build --profile optimized $(FEATURES_CONCURRENT_EXEC)

.PHONY: exec-single
exec-single: ## Builds a single-threaded executable
	cargo build --profile optimized --features executable

.PHONY: exec-metal
exec-metal: ## Builds an executable with Metal acceleration enabled
	cargo build --profile optimized $(FEATURES_METAL_EXEC)

.PHONY: exec-avx2
exec-avx2: ## Builds an executable with AVX2 acceleration enabled
	RUSTFLAGS="-C target-feature=+avx2" cargo build --profile optimized $(FEATURES_CONCURRENT_EXEC)

.PHONY: exec-sve
exec-sve: ## Builds an executable with SVE acceleration enabled
	RUSTFLAGS="-C target-feature=+sve" cargo build --profile optimized $(FEATURES_CONCURRENT_EXEC)

.PHONY: exec-info
exec-info: ## Builds an executable with log tree enabled
	cargo build --profile optimized $(FEATURES_LOG_TREE)

# --- benchmarking --------------------------------------------------------------------------------

.PHONY: bench
bench: ## Runs benchmarks
	cargo bench --profile optimized --features internal
