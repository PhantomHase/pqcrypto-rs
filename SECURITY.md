# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

Please use [GitHub's private vulnerability reporting](https://github.com/PhantomHase/pqcrypto-rs/security/advisories/new) to report security issues. This ensures responsible disclosure and allows us to address the issue before public disclosure.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Depends on severity
  - Critical: Within 24-48 hours
  - High: Within 1 week
  - Medium: Within 2 weeks
  - Low: Next release

## Security Considerations

This is a **cryptographic library**. Security is paramount.

### Design Principles

1. **No unsafe code** — enforced via `#![forbid(unsafe_code)]` on all crates
2. **Constant-time operations** — all crypto operations resist timing attacks via `subtle` crate
3. **Zeroization** — secret keys are zeroized from memory after use via `Drop` trait
4. **NIST compliance** — algorithms follow FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)

### Known Limitations

- Polynomial multiplication uses schoolbook O(n²) — negacyclic NTT planned for optimization
- KEM round-trip has lossy compression precision issues (marked `#[ignore]` in tests)
- SLH-DSA is a stub implementation only
- ML-DSA uses a custom hint encoding (±1 direction) instead of standard FIPS 204 MakeHint/UseHint

### What we consider a vulnerability

- Timing side-channels in cryptographic operations
- Memory leaks of secret key material
- Incorrect algorithm implementation vs. NIST specifications
- Dependency vulnerabilities affecting cryptographic operations
- Unsafe memory access patterns

### What is NOT a vulnerability

- Performance issues (unless they leak timing information)
- Missing features or incomplete implementations
- Known limitations documented in [README.md](README.md)
