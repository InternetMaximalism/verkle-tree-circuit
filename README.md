# Bellman Sample

## Environment

```sh
cargo --version # >= 1.56.0
```

## How to test

```sh
cargo test
```

## How to use

```sh
cargo run # help
cargo run setup tests/proving_key tests/verifying_key
cargo run prove tests/proving_key tests/input.json tests/proof tests/public_wires.txt
cargo run verify tests/verifying_key tests/proof tests/public_wires.txt
```
