# Contributing to PQCrypto-RS

Thank you for your interest in contributing to PQCrypto-RS!

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch: `git checkout -b feature/my-feature`
4. Make your changes
5. Run tests: `cargo test`
6. Run clippy: `cargo clippy`
7. Commit your changes
8. Push to your fork
9. Open a Pull Request

## Workspace Architecture

The workspace contains the following crates:
- `pqcrypto-core` - Mathematical primitives (NTT, reduction, sampling)
- `pqcrypto-kem` - ML-KEM-768 key encapsulation implementation
- `pqcrypto-sign` - ML-DSA-65 and SLH-DSA-SHA2-128s signature implementations
- `pqcrypto-wasm` - WebAssembly bindings (`wasm-bindgen`)
- `pqcrypto-cli` - CommandLine interface facade

## Development Setup

```bash
# Clone the repository
git clone https://github.com/PhantomHase/pqcrypto-rs.git
cd pqcrypto-rs

# Build the workspace
cargo build --workspace

# Run tests
cargo test --workspace

# Run benchmarks
cargo bench
```

### WebAssembly Setup
To build the WASM package and run the interactive browser playground, set up the wasm32 target and wasm-pack compiler:
```bash
# Add the wasm32 target
rustup target add wasm32-unknown-unknown

# Install wasm-pack
cargo install wasm-pack

# Compile the WASM bindings
wasm-pack build pqcrypto-wasm --target web

# Run WASM tests on host target
cargo test -p pqcrypto-wasm
```


## Code Style

- Follow Rust standard style (use `cargo fmt`)
- No `unsafe` code (enforced by `#![forbid(unsafe_code)]`)
- All crypto operations must be constant-time where applicable
- Use `subtle` crate for constant-time comparisons
- Use `zeroize` for sensitive data cleanup
- Document all public APIs with doc comments

## Testing

- Write unit tests for all new functions
- Include property-based tests with `proptest` where applicable
- Known Answer Tests (KAT) from NIST specifications should be included
- All tests must pass before submitting a PR

## Security

- Report security vulnerabilities privately to the maintainers
- Do NOT open public issues for security vulnerabilities
- Follow responsible disclosure practices

## License

By contributing, you agree that your contributions will be dual-licensed
under Apache 2.0 and MIT.
