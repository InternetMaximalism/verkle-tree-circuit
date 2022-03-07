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
cargo run crs create # create common reference string (CRS) for PlonK
```

## How to test

```sh
RUST_BACKTRACE=1 cargo test -- --nocapture
```
