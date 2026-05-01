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

## Development Setup

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone the repository
git clone https://github.com/PhantomHase/pqcrypto-rs.git
cd pqcrypto-rs

# Build
cargo build

# Test
cargo test

# Bench
cargo bench
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
