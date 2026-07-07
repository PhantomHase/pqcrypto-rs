# Project: pqcrypto-rs Phase 5 Roadmap Implementation

## Architecture
This project is a workspace containing Rust implementations of post-quantum cryptography algorithms. Phase 5 adds WebAssembly integration, an interactive playground, documentation, and contributing guidelines.
The architecture consists of:
- `pqcrypto-wasm`: A new workspace crate wrapping existing KEM and Sign APIs with `wasm-bindgen`.
- Browser Playground: Single-page application (`index.html`, `index.js`, styling) using the WASM module directly via ES modules.
- Documentation: `mdBook` configuration and source files, and warning-free `cargo doc`.
- Guidelines: `CONTRIBUTING.md` updating workspace layout, coding standards, and build/test/WASM development instructions.

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | WebAssembly Crate (`pqcrypto-wasm`) | Create crate, implement `wasm-bindgen` bindings for ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128s, and build via `wasm-pack` | none | DONE |
| 2 | Interactive Playground | Develop `index.html`, `index.js`, and styling with tabs, dark mode, and operations | M1 | DONE |
| 3 | Documentation (mdBook & rustdoc) | Initialize `book`, write theoretical/usage docs, verify warning-free cargo doc | none | DONE |
| 4 | Contributing Guidelines | Update `CONTRIBUTING.md` with workspace architecture and build/test instructions | none | DONE |
| 5 | E2E Verification & Audit | Ensure all tests pass, build completes, playground functions, and run forensic audit | M1, M2, M3, M4 | DONE |

## Interface Contracts
### `pqcrypto-wasm` JS Bindings
- **ML-KEM-768**:
  - `ml_kem_768_keygen() -> MlKemKeyPair`
  - `ml_kem_768_encapsulate(pk_hex_or_b64: &str) -> MlKemEncapsResult`
  - `ml_kem_768_decapsulate(sk_hex_or_b64: &str, ct_hex_or_b64: &str) -> String` (returns shared secret hex/b64)
- **ML-DSA-65**:
  - `ml_dsa_65_keygen() -> MlDsaKeyPair`
  - `ml_dsa_65_sign(sk_hex_or_b64: &str, message: &[u8]) -> String` (returns signature hex/b64)
  - `ml_dsa_65_verify(pk_hex_or_b64: &str, message: &[u8], sig_hex_or_b64: &str) -> bool`
- **SLH-DSA-SHA2-128s**:
  - `slh_dsa_128s_keygen() -> SlhDsaKeyPair`
  - `slh_dsa_128s_sign(sk_hex_or_b64: &str, message: &[u8]) -> String` (returns signature hex/b64)
  - `slh_dsa_128s_verify(pk_hex_or_b64: &str, message: &[u8], sig_hex_or_b64: &str) -> bool`

## Code Layout
- `pqcrypto-wasm/` - Dedicated crate for WASM integration.
- `playground/` - Visual playground files (`index.html`, `index.js`, `style.css`).
- `book/` - mdBook documentation folder.
- `CONTRIBUTING.md` - Contribution guide.
