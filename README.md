# Verkle Tree Circuit

## Environment

```sh
rustup override set nightly
cargo --version # >= 1.56.0
```

## API

```sh
git clone git@github.com:InternetMaximalism/verkle-tree-circuit.git
git submodule init
git submodule update
cargo test --package verkle-circuit --lib -- crs::crs_tests::test_crs_serialization --exact --nocapture # create common reference string (CRS) for PlonK
```

**The Verkle tree circuit verification does not work yet.**

## How to test

```sh
RUST_BACKTRACE=1 cargo test -- --nocapture
```
