cd packages/neptune-js
cargo clean
cargo build --release --target x86_64-unknown-linux-gnu
cp ../../target/release/libneptune_js.dylib index.node
