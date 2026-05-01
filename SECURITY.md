# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security vulnerabilities by emailing:

**omarfaza.alkautsar@gmail.com**

Or use [GitHub's private vulnerability reporting](https://github.com/PhantomHase/pqcrypto-rs/security/advisories/new).

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

This is a **cryptographic library**. Security is paramount:

### Design Principles

1. **No unsafe code** — enforced via `#![forbid(unsafe_code)]`
2. **Constant-time operations** — all crypto operations resist timing attacks
3. **Zeroization** — secret keys are zeroized from memory after use
4. **NIST compliance** — algorithms follow FIPS 203, 204, 205 specifications

### Known Limitations

- The NTT implementation uses schoolbook multiplication (O(n²)) — not optimized for constant-time
- ML-DSA signing has known issues (see test ignores)
- KEM round-trip has lossy compression precision issues

### What we consider a vulnerability

- Timing side-channels in crypto operations
- Memory leaks of secret key material
- Incorrect algorithm implementation vs. NIST specifications
- Dependency vulnerabilities affecting crypto operations

### What is NOT a vulnerability

- Performance issues (unless they leak timing information)
- Missing features or incomplete implementations
- Known limitations documented in README.md
