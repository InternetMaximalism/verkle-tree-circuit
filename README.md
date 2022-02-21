# Verkle Tree Circuit

## Environment

```sh
rustup override set nightly
cargo --version # >= 1.56.0
```

```
git clone git@github.com:InternetMaximalism/verkle-tree-circuit.git
git submodule init
git submodule update
```

## How to test

```sh
RUST_BACKTRACE=1 cargo test -- --nocapture
```
