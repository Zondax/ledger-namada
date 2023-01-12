[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GithubActions](https://github.com/Zondax/ledger-namada/actions/workflows/main.yml/badge.svg)](https://github.com/Zondax/ledger-namada/blob/main/.github/workflows/main.yaml)

---

![zondax_light](../docs/zondax_light.png#gh-light-mode-only)
![zondax_dark](../docs/zondax_dark.png#gh-dark-mode-only)

_Please visit our website at [zondax.ch](https://www.zondax.ch)_

---

# Rust library for Ledger Namada app

This package provides a basic Rust client library to communicate with the Filecoin App running in a Ledger Nano S/S+/X devices

## Build

- Install rust using the instructions [here](https://www.rust-lang.org/tools/install)
- To build run:
```shell script
cargo build
```

## Run Tests
To run the tests

- Initialize your device with the test mnemonic. More info [here](https://github.com/zondax/ledger-filecoin#set-test-mnemonic)
- run tests using:
```shell script
cargo test --all
```
