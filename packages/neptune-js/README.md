# Neptune JS

This project was bootstrapped by [create-neon](https://www.npmjs.com/package/create-neon).

## Installing neptune-js

Installing neptune-js requires a [supported version of Node and Rust](https://github.com/neon-bindings/neon#platform-support).

```sh
$ rustup override set nightly-x86_64-apple-darwin # Not use nightly-aarch-apple-darwin
```

You can install the project with npm. In the project directory, run:

```sh
$ yarn
```

This fully installs the project, including installing any dependencies and running the build.

## Building neptune-js

If you have already installed the project and only want to run the build, run:

```sh
$ yarn build
```

This command uses the [cargo-cp-artifact](https://github.com/neon-bindings/cargo-cp-artifact) utility to run the Rust build and copy the built library into `./index.node`.
