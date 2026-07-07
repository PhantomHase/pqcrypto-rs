# Installation & Build

## Prerequisites
To compile and build PQCrypto-RS, you need the standard Rust toolchain:
- **Rust Edition 2021** (Rust 1.70+)
- **Cargo** package manager

If you wish to compile the library to WebAssembly and run the interactive browser playground, you will also need:
- **wasm-pack** tool
- **Node.js & npm** (for the local server and playground dependencies)

## Adding to Cargo.toml
Add the respective crates to your project's `Cargo.toml`:
```toml
[dependencies]
pqcrypto-core = { path = "path/to/pqcrypto-core" }
pqcrypto-kem = { path = "path/to/pqcrypto-kem" }
pqcrypto-sign = { path = "path/to/pqcrypto-sign" }
```

## Compilation
Build all crates in the workspace:
```bash
cargo build --workspace
```

For release optimization:
```bash
cargo build --workspace --release
```

## Running Tests
Run all unit and integration tests:
```bash
cargo test --workspace
```
Note: SLH-DSA tests involve complex hypertree structure computations and can be slow in debug mode. Consider running in release mode for faster testing:
```bash
cargo test --workspace --release
```
