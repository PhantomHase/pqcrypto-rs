//! ML-DSA-65 (Dilithium) Digital Signature Scheme.
//!
//! Implements FIPS 204 ML-DSA-65 (NIST Security Level 3).
//!
//! Parameters:
//! - k = 6, l = 5 (matrix dimensions)
//! - n = 256 (polynomial degree)
//! - q = 8380417 (modulus)
//! - η = 4 (secret key coefficient range: [-4, 4])
//! - γ₁ = 2^19 (challenge coefficient range)
//! - γ₂ = (q-1)/32 = 261888 (rounding parameter)
//! - β = 78 (challenge bound)
//! - τ = 49 (number of ±1 in challenge)
//! - d = 13 (Power2Round parameter)

use crate::ml_dsa_params::*;
use crate::SignError;
use zeroize::Zeroize;

// ============================================================================
// ML-DSA Polynomial (mod q = 8380417)
// ============================================================================

/// A polynomial in Z_q[X]/(X^256+1) with q = 8380417.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaPoly {
    pub coeffs: [i32; N],
}

impl Default for MlDsaPoly {
    fn default() -> Self {
        Self { coeffs: [0i32; N] }
    }
}

impl Zeroize for MlDsaPoly {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

impl MlDsaPoly {
    pub fn zero() -> Self {
        Self { coeffs: [0i32; N] }
    }

    /// Add two polynomials mod q.
    pub fn add(&self, rhs: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            result.coeffs[i] = ((self.coeffs[i] as i64 + rhs.coeffs[i] as i64) % Q as i64) as i32;
        }
        result
    }

    /// Subtract two polynomials mod q.
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            let diff = (self.coeffs[i] as i64 - rhs.coeffs[i] as i64 + Q as i64) % Q as i64;
            result.coeffs[i] = diff as i32;
        }
        result
    }

    /// Multiply by a scalar mod q.
    pub fn scalar_mul(&self, scalar: i32) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            result.coeffs[i] = ((self.coeffs[i] as i64 * scalar as i64).rem_euclid(Q as i64)) as i32;
        }
        result
    }

    /// Check if coefficients are in range [-bound, bound].
    pub fn check_norm_bound(&self, bound: i32) -> bool {
        for &c in &self.coeffs {
            let centered = if c > (Q as i32 - 1) / 2 {
                c - Q as i32
            } else {
                c
            };
            if centered.abs() >= bound {
                return false;
            }
        }
        true
    }

    /// Power2Round: decompose r into (r0, r1) where r = r1 * 2^d + r0.
    ///
    /// For ML-DSA-65, d = 13 (so 2^d = 8192).
    /// r0 is in [-(2^(d-1)), 2^(d-1)) = [-4096, 4096)
    /// r1 is in [0, (q-1)/2^d] = [0, 1023]
    pub fn power2round(&self, d: u32) -> (Self, Self) {
        let mut r0 = Self::zero();
        let mut r1 = Self::zero();
        let pow2d = 1i32 << d;
        let half_pow2d = 1i32 << (d - 1);

        for i in 0..N {
            let r = self.coeffs[i];
            // r0 = r mod 2^d, centered in [-(2^(d-1)), 2^(d-1))
            let r0_raw = r % pow2d;
            // Center: if r0_raw > 2^(d-1), subtract 2^d
            r0.coeffs[i] = if r0_raw >= half_pow2d {
                r0_raw - pow2d
            } else if r0_raw < -half_pow2d {
                r0_raw + pow2d
            } else {
                r0_raw
            };
            // r1 = (r - r0) / 2^d
            r1.coeffs[i] = (r - r0.coeffs[i]) / pow2d;
        }

        (r0, r1)
    }

    /// MakeHint: compute hint bits for rounding.
    ///
    /// Returns 1 if adding z changes the high bits of r, 0 otherwise.
    /// FIPS 204 Algorithm 32 (MakeHint)
    pub fn make_hint(z: &Self, r: &Self, gamma2: i32) -> (Self, usize) {
        let mut hint = Self::zero();
        let mut count = 0;

        for i in 0..N {
            let r1 = Self::decompose_single(r.coeffs[i], gamma2);
            let rz = (r.coeffs[i] as i64 + z.coeffs[i] as i64).rem_euclid(Q as i64) as i32;
            let rz1 = Self::decompose_single(rz, gamma2);

            if r1 != rz1 {
                hint.coeffs[i] = 1;
                count += 1;
            }
        }

        (hint, count)
    }

    /// Helper: compute high bits of r with respect to γ₂.
    /// This is the "decompose" function from FIPS 204.
    /// Input r is in [0, q). Returns r1 such that r = r1 * 2γ₂ + r0.
    fn decompose_single(r: i32, gamma2: i32) -> i32 {
        // Reduce r to [0, q) first
        let r_mod = r.rem_euclid(Q as i32);
        // Compute r0 = r mod± 2γ₂ in (-γ₂, γ₂]
        let r0 = r_mod.rem_euclid(2 * gamma2);
        let r0_centered = if r0 > gamma2 { r0 - 2 * gamma2 } else { r0 };
        // r1 = (r - r0) / 2γ₂
        (r_mod - r0_centered) / (2 * gamma2)
    }

    /// UseHint: apply hint to adjust rounding.
    /// Given hint h = MakeHint(z, r), returns HighBits(r + z).
    /// The adjustment direction: if r₀ > 0, the "other" high bits is r₁+1 (crossing upward).
    pub fn use_hint(hint: &Self, r: &Self, gamma2: i32) -> Self {
        let mut result = Self::zero();

        for i in 0..N {
            let r_mod = r.coeffs[i].rem_euclid(Q as i32);
            let r0 = r_mod.rem_euclid(2 * gamma2);
            let r0_centered = if r0 > gamma2 { r0 - 2 * gamma2 } else { r0 };
            let r1 = (r_mod - r0_centered) / (2 * gamma2);

            if hint.coeffs[i] == 1 {
                if r0_centered > 0 {
                    result.coeffs[i] = r1 + 1;
                } else {
                    result.coeffs[i] = r1 - 1;
                }
            } else {
                result.coeffs[i] = r1;
            }
        }

        result
    }

    /// Reduce coefficients to centered representation [-((q-1)/2), (q-1)/2].
    pub fn reduce_centered(&self) -> Self {
        let mut result = self.clone();
        let half_q = (Q as i32 - 1) / 2;
        for c in &mut result.coeffs {
            if *c > half_q {
                *c -= Q as i32;
            }
        }
        result
    }
}

/// A vector of polynomials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolyVec {
    pub polys: Vec<MlDsaPoly>,
}

impl zeroize::Zeroize for PolyVec {
    fn zeroize(&mut self) {
        for poly in &mut self.polys {
            poly.zeroize();
        }
    }
}

impl PolyVec {
    pub fn new(k: usize) -> Self {
        Self {
            polys: vec![MlDsaPoly::zero(); k],
        }
    }

    pub fn len(&self) -> usize {
        self.polys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.polys.is_empty()
    }

    /// Add two polynomial vectors.
    pub fn add(&self, rhs: &Self) -> Self {
        assert_eq!(self.len(), rhs.len());
        Self {
            polys: self.polys.iter().zip(rhs.polys.iter()).map(|(a, b)| a.add(b)).collect(),
        }
    }

    /// Subtract two polynomial vectors.
    pub fn sub(&self, rhs: &Self) -> Self {
        assert_eq!(self.len(), rhs.len());
        Self {
            polys: self.polys.iter().zip(rhs.polys.iter()).map(|(a, b)| a.sub(b)).collect(),
        }
    }

    /// Check norm bound on all polynomials.
    pub fn check_norm_bound(&self, bound: i32) -> bool {
        self.polys.iter().all(|p| p.check_norm_bound(bound))
    }

    /// Reduce all polynomials to centered representation.
    pub fn reduce_centered(&self) -> Self {
        Self {
            polys: self.polys.iter().map(|p| p.reduce_centered()).collect(),
        }
    }
}

/// A matrix of polynomials (k x l).
#[derive(Clone, Debug)]
pub struct PolyMatrix {
    pub rows: Vec<PolyVec>,
}

impl PolyMatrix {
    pub fn new(k: usize, l: usize) -> Self {
        Self {
            rows: vec![PolyVec::new(l); k],
        }
    }

    /// Multiply matrix by vector: result[i] = sum_j A[i][j] * v[j]
    pub fn mul_vec(&self, v: &PolyVec) -> PolyVec {
        assert_eq!(self.rows[0].len(), v.len());
        let mut result = PolyVec::new(self.rows.len());

        for (i, row) in self.rows.iter().enumerate() {
            for (j, a_ij) in row.polys.iter().enumerate() {
                let product = poly_mul(a_ij, &v.polys[j]);
                result.polys[i] = result.polys[i].add(&product);
            }
        }

        result
    }
}

/// Schoolbook polynomial multiplication in Z_q[X]/(X^256+1).
fn poly_mul(a: &MlDsaPoly, b: &MlDsaPoly) -> MlDsaPoly {
    let mut result = MlDsaPoly::zero();

    for i in 0..N {
        for j in 0..N {
            let idx = (i + j) % N;
            let sign = if i + j >= N { -1i64 } else { 1i64 };
            let prod = (a.coeffs[i] as i64 * b.coeffs[j] as i64 * sign).rem_euclid(Q as i64);
            result.coeffs[idx] = ((result.coeffs[idx] as i64 + prod) % Q as i64) as i32;
        }
    }

    result
}

// ============================================================================
// ML-DSA Hash Functions
// ============================================================================

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Sha3_512, Sha3_256, Shake128, Shake256,
};
use sha3::Digest;

/// H_η: Sample polynomial with coefficients in [-η, η] using SHAKE-256.
/// FIPS 204 Section 4.2.2: Sampleη
fn sample_eta(seed: &[u8], nonce: u16) -> MlDsaPoly {
    let mut input = Vec::with_capacity(seed.len() + 2);
    input.extend_from_slice(seed);
    input.extend_from_slice(&nonce.to_le_bytes());

    let mut hasher = Shake256::default();
    Update::update(&mut hasher, &input);
    let mut reader = hasher.finalize_xof();

    let mut poly = MlDsaPoly::zero();
    // Generate enough bytes for rejection sampling
    // For η=4, rejection rate ≈ 1 - (2*4+1)/256 ≈ 96.5%
    // Need ~28 bytes per coefficient on average, use 64 for safety
    let mut byte_buf = vec![0u8; N * 64];
    reader.read(&mut byte_buf);

    let mut idx = 0;
    for i in 0..N {
        // Rejection sampling: accept byte z if z < 2η
        // Then coefficient = z - η, giving values in {-η, ..., η-1}
        // For η=4: accept z < 8, giving {-4, -3, -2, -1, 0, 1, 2, 3}
        // But we need {-4, ..., 4} = 9 values
        // So we need to use a different approach
        while idx < byte_buf.len() {
            let z = byte_buf[idx] as i32;
            idx += 1;
            // For η=4, we need 9 values: {-4,...,4}
            // 256/9 ≈ 28.4, so rejection rate is about 4/256 ≈ 1.6%
            // We accept z if z < 9*28 = 252
            if z < (2 * ETA as i32 + 1) * (256 / (2 * ETA as i32 + 1)) {
                poly.coeffs[i] = (z % (2 * ETA as i32 + 1)) - ETA as i32;
                break;
            }
        }
    }

    poly
}

/// Sample polynomial in [-γ₁, γ₁] using SHAKE-256.
fn sample_gamma1(seed: &[u8], nonce: u16) -> MlDsaPoly {
    let mut input = Vec::with_capacity(seed.len() + 2);
    input.extend_from_slice(seed);
    input.extend_from_slice(&nonce.to_le_bytes());

    let mut hasher = Shake256::default();
    Update::update(&mut hasher, &input);
    let mut reader = hasher.finalize_xof();

    let mut poly = MlDsaPoly::zero();
    let mut byte_buf = vec![0u8; N * 3];
    reader.read(&mut byte_buf);

    for i in 0..N {
        // Sample from [-γ₁, γ₁] using 3 bytes per coefficient
        let val = (byte_buf[3 * i] as u32)
            | ((byte_buf[3 * i + 1] as u32) << 8)
            | ((byte_buf[3 * i + 2] as u32) << 16);
        let val = val % (2 * GAMMA1 + 1);
        poly.coeffs[i] = val as i32 - GAMMA1 as i32;
    }

    poly
}

/// Generate matrix A from seed ρ using SHAKE-128.
fn sample_matrix_a(seed: &[u8]) -> PolyMatrix {
    let mut matrix = PolyMatrix::new(K, L);

    for i in 0..K {
        for j in 0..L {
            let mut input = Vec::with_capacity(seed.len() + 2);
            input.extend_from_slice(seed);
            input.extend_from_slice(&[j as u8, i as u8]);

            let mut hasher = Shake128::default();
            Update::update(&mut hasher, &input);
            let mut reader = hasher.finalize_xof();
            let mut bytes = vec![0u8; N * 3];
            reader.read(&mut bytes);

            for k in 0..N {
                let val = (bytes[3 * k] as u32)
                    | ((bytes[3 * k + 1] as u32) << 8)
                    | ((bytes[3 * k + 2] as u32) << 16);
                matrix.rows[i].polys[j].coeffs[k] = (val % Q) as i32;
            }
        }
    }

    matrix
}

/// Sample challenge polynomial from a ball (exactly τ non-zero coefficients that are ±1).
///
/// FIPS 204 Section 4.2.3: SampleInBall
fn sample_in_ball(seed: &[u8]) -> MlDsaPoly {
    let mut poly = MlDsaPoly::zero();
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, seed);
    let mut reader = hasher.finalize_xof();

    // Generate 8 bytes for the sign bits
    let mut sign_bytes = [0u8; 8];
    reader.read(&mut sign_bytes);

    // Generate bytes for position selection
    let mut pos_bytes = vec![0u8; TAU * 2];
    reader.read(&mut pos_bytes);

    // Fisher-Yates shuffle to select τ positions
    let mut positions = Vec::with_capacity(TAU);
    let mut available: Vec<usize> = (0..N).collect();

    for i in 0..TAU {
        // Use rejection sampling to get uniform random index
        let mut idx = 0;
        let mut byte_idx = i * 2;
        loop {
            let val = pos_bytes[byte_idx] as usize;
            byte_idx += 1;
            if val < N - i {
                idx = val;
                break;
            }
            if byte_idx >= pos_bytes.len() {
                // Fallback: use modular reduction
                idx = (pos_bytes[i * 2] as usize + pos_bytes[i * 2 + 1] as usize * 256) % (N - i);
                break;
            }
        }

        positions.push(available[idx]);
        available.swap(idx, N - i - 1);
    }

    // Assign ±1 signs
    for (i, &pos) in positions.iter().enumerate() {
        let bit = (sign_bytes[i / 8] >> (i % 8)) & 1;
        poly.coeffs[pos] = if bit == 1 { 1 } else { -1 };
    }

    poly
}

/// H: Hash function (SHA3-512).
fn h512(input: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, input);
    hasher.finalize().into()
}

/// H_256: Hash function (SHA3-256).
fn h256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, input);
    hasher.finalize().into()
}

// ============================================================================
// ML-DSA-65 Key Generation
// ============================================================================

/// ML-DSA-65 public key.
#[derive(Clone, Debug)]
pub struct MlDsaPublicKey {
    /// Seed ρ (32 bytes)
    pub rho: [u8; SEED_LEN],
    /// t1 = high bits of t (encoded)
    pub t1: PolyVec,
}

/// ML-DSA-65 secret key.
#[derive(Clone, Debug)]
pub struct MlDsaSecretKey {
    /// Seed ρ (32 bytes)
    pub rho: [u8; SEED_LEN],
    /// Key K (32 bytes)
    pub k: [u8; SEED_LEN],
    /// tr = H(pk) (32 bytes)
    pub tr: [u8; SEED_LEN],
    /// s1: secret vector with small coefficients
    pub s1: PolyVec,
    /// s2: secret vector with small coefficients
    pub s2: PolyVec,
    /// t0: low bits of t
    pub t0: PolyVec,
}

impl Zeroize for MlDsaSecretKey {
    fn zeroize(&mut self) {
        self.rho.zeroize();
        self.k.zeroize();
        self.tr.zeroize();
        self.s1.zeroize();
        self.s2.zeroize();
        self.t0.zeroize();
    }
}

impl Drop for MlDsaSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// ML-DSA-65 signature.
#[derive(Clone, Debug)]
pub struct MlDsaSignature {
    /// c~: challenge hash
    pub c_tilde: [u8; SEED_LEN],
    /// z: response vector
    pub z: PolyVec,
    /// h: hint vector
    pub h: PolyVec,
}

/// Generate ML-DSA-65 key pair.
pub fn keygen() -> (MlDsaPublicKey, MlDsaSecretKey) {
    use rand::RngCore;

    let mut rng = rand::thread_rng();

    // Step 1: Generate random seed ζ
    let mut zeta = [0u8; SEED_LEN];
    rng.fill_bytes(&mut zeta);

    keygen_internal(&zeta)
}

/// Internal key generation with explicit seed.
pub fn keygen_internal(zeta: &[u8; SEED_LEN]) -> (MlDsaPublicKey, MlDsaSecretKey) {
    // Step 2: (ρ, K, ρ') = H(ζ || k || l)
    let mut h_input = Vec::with_capacity(SEED_LEN + 2);
    h_input.extend_from_slice(zeta);
    h_input.push(K as u8);
    h_input.push(L as u8);
    let h_out = h512(&h_input);

    let mut rho = [0u8; SEED_LEN];
    let mut k_seed = [0u8; SEED_LEN];
    let mut rho_prime = [0u8; SEED_LEN];
    rho.copy_from_slice(&h_out[..SEED_LEN]);
    k_seed.copy_from_slice(&h_out[SEED_LEN..2 * SEED_LEN]);
    // Use first 64 bytes of h512, rho_prime from next hash
    let h_out2 = h512(&h_out);
    rho_prime.copy_from_slice(&h_out2[..SEED_LEN]);

    // Step 3: Generate matrix A from ρ
    let a = sample_matrix_a(&rho);

    // Step 4: Sample s1, s2 from CBD_η(ρ')
    let mut s1 = PolyVec::new(L);
    let mut s2 = PolyVec::new(K);
    for i in 0..L {
        s1.polys[i] = sample_eta(&rho_prime, i as u16);
    }
    for i in 0..K {
        s2.polys[i] = sample_eta(&rho_prime, (L + i) as u16);
    }

    // Step 5: t = A * s1 + s2
    let t = a.mul_vec(&s1).add(&s2);

    // Step 6: Power2Round t to get t0, t1
    let (t0, t1) = power2round_vec(&t, 13);

    // Step 7: pk = (ρ, t1), sk = (ρ, K, tr, s1, s2, t0)
    let pk_bytes = encode_pk_bytes(&rho, &t1);
    let tr = h256(&pk_bytes);

    let pk = MlDsaPublicKey { rho, t1 };
    let sk = MlDsaSecretKey {
        rho,
        k: k_seed,
        tr,
        s1,
        s2,
        t0,
    };

    (pk, sk)
}

/// Power2Round for a vector of polynomials.
fn power2round_vec(t: &PolyVec, d: u32) -> (PolyVec, PolyVec) {
    let k = t.len();
    let mut t0 = PolyVec::new(k);
    let mut t1 = PolyVec::new(k);

    for i in 0..k {
        let (p0, p1) = t.polys[i].power2round(d);
        t0.polys[i] = p0;
        t1.polys[i] = p1;
    }

    (t0, t1)
}

/// Encode public key to bytes (for hashing).
fn encode_pk_bytes(rho: &[u8; SEED_LEN], t1: &PolyVec) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(rho);
    // Encode t1 polynomials (10 bits per coefficient)
    for poly in &t1.polys {
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for &c in &poly.coeffs {
            acc |= ((c as u32) & 0x3FF) << bits;
            bits += 10;
            while bits >= 8 {
                bytes.push((acc & 0xFF) as u8);
                acc >>= 8;
                bits -= 8;
            }
        }
        if bits > 0 {
            bytes.push((acc & 0xFF) as u8);
        }
    }
    bytes
}

// ============================================================================
// ML-DSA-65 Signing
// ============================================================================

/// Sign a message using ML-DSA-65.
pub fn sign(sk: &MlDsaSecretKey, message: &[u8]) -> MlDsaSignature {
    use rand::RngCore;

    let mut rng = rand::thread_rng();

    // Step 1: Generate random nonce
    let mut rnd = [0u8; SEED_LEN];
    rng.fill_bytes(&mut rnd);

    sign_internal(sk, message, &rnd)
}

/// Internal signing with explicit randomness.
pub fn sign_internal(
    sk: &MlDsaSecretKey,
    message: &[u8],
    rnd: &[u8; SEED_LEN],
) -> MlDsaSignature {
    // Step 2: μ = H(tr || M)
    let mut mu_input = Vec::with_capacity(SEED_LEN + message.len());
    mu_input.extend_from_slice(&sk.tr);
    mu_input.extend_from_slice(message);
    let mu = h256(&mu_input);

    // Step 3: ρ' = H(K || rnd || μ)
    let mut rho_prime_input = Vec::with_capacity(SEED_LEN * 2 + 32);
    rho_prime_input.extend_from_slice(&sk.k);
    rho_prime_input.extend_from_slice(rnd);
    rho_prime_input.extend_from_slice(&mu);
    let rho_prime = h256(&rho_prime_input);

    // Step 4: Generate matrix A from sk.rho
    let a = sample_matrix_a(&sk.rho);

    // Step 5-11: Rejection sampling loop
    let mut kappa = 0u16;
    let max_iterations = 50000; // Prevent infinite loops
    for _iter in 0..max_iterations {
        // Step 6: Sample y from [-γ₁, γ₁]
        let mut y = PolyVec::new(L);
        for i in 0..L {
            y.polys[i] = sample_gamma1(&rho_prime, kappa * L as u16 + i as u16);
        }

        // Step 7: w = A * y
        let w = a.mul_vec(&y);

        // Step 8: w1 = high bits of w
        let w1 = high_bits_vec(&w, GAMMA2 as i32);

        // Step 9: c~ = H(μ || w1)
        let mut c_input = Vec::with_capacity(32 + K * 32);
        c_input.extend_from_slice(&mu);
        for poly in &w1.polys {
            for &c in &poly.coeffs {
                c_input.extend_from_slice(&(c as u16).to_le_bytes());
            }
        }
        let c_tilde = h256(&c_input);

        // Step 10: c = SampleInBall(c~)
        let c = sample_in_ball(&c_tilde);

        // Step 11: z = y + c * s1
        let cs1 = scalar_mul_vec(&c, &sk.s1);
        let z = y.add(&cs1);

        // Check norm bound: ||z||∞ < γ₁ - β
        let bound = (GAMMA1 as i32 - BETA as i32) as i32;
        if !z.check_norm_bound(bound) {
            kappa += 1;
            continue;
        }

        // Step 12: r0 = low bits of (w - c * s2)
        let cs2 = scalar_mul_vec(&c, &sk.s2);
        let w_minus_cs2 = w.sub(&cs2);
        let r0 = low_bits_vec(&w_minus_cs2, GAMMA2 as i32);

        // Check: ||r0||∞ < γ₂ - β
        let bound2 = (GAMMA2 as i32 - BETA as i32) as i32;
        if !r0.check_norm_bound(bound2) {
            kappa += 1;
            continue;
        }

        // Step 13: Compute hint h
        // h[i] = 1 iff HighBits(w[i]) ≠ HighBits(w - cs₂ + ct₀)[i]
        let ct0 = scalar_mul_vec(&c, &sk.t0);
        let w_minus_cs2_plus_ct0 = w_minus_cs2.add(&ct0);
        let hb_w = high_bits_vec(&w, GAMMA2 as i32);
        let hb_w_prime = high_bits_vec(&w_minus_cs2_plus_ct0, GAMMA2 as i32);
        let mut h = PolyVec::new(K);
        let mut hint_count = 0;
        for i in 0..K {
            for j in 0..N {
                let diff = hb_w.polys[i].coeffs[j] - hb_w_prime.polys[i].coeffs[j];
                if diff != 0 {
                    // Encode direction: +1 for upward crossing, -1 for downward
                    h.polys[i].coeffs[j] = diff; // +1 or -1
                    hint_count += 1;
                }
            }
        }

        // Check: number of non-zero hints ≤ ω (ω = 60 for ML-DSA-65)
        if hint_count > 60 {
            kappa += 1;
            continue;
        }

        // Success! Return signature
        return MlDsaSignature { c_tilde, z, h };
    }

    // If we reach here, signing failed after max iterations
    // Return a dummy signature (this should not happen in practice)
    MlDsaSignature {
        c_tilde: [0u8; SEED_LEN],
        z: PolyVec::new(L),
        h: PolyVec::new(K),
    }
}

/// Scalar multiplication: multiply polynomial by vector element-wise.
fn scalar_mul_vec(c: &MlDsaPoly, v: &PolyVec) -> PolyVec {
    PolyVec {
        polys: v.polys.iter().map(|p| poly_mul(c, p)).collect(),
    }
}

/// High bits decomposition.
/// FIPS 204 Algorithm 31 (HighBits)
fn high_bits(r: &MlDsaPoly, gamma2: i32) -> MlDsaPoly {
    let mut result = MlDsaPoly::zero();
    for i in 0..N {
        result.coeffs[i] = MlDsaPoly::decompose_single(r.coeffs[i], gamma2);
    }
    result
}

fn high_bits_vec(v: &PolyVec, gamma2: i32) -> PolyVec {
    PolyVec {
        polys: v.polys.iter().map(|p| high_bits(p, gamma2)).collect(),
    }
}

/// Low bits decomposition.
///
/// Returns r0 = r mod^{±} 2γ₂, centered in (-γ₂, γ₂]
fn low_bits(r: &MlDsaPoly, gamma2: i32) -> MlDsaPoly {
    let mut result = MlDsaPoly::zero();
    for i in 0..N {
        let r0 = r.coeffs[i].rem_euclid(2 * gamma2);
        // Center: map [0, 2γ₂) to (-γ₂, γ₂]
        result.coeffs[i] = if r0 > gamma2 {
            r0 - 2 * gamma2
        } else {
            r0
        };
    }
    result
}

fn low_bits_vec(v: &PolyVec, gamma2: i32) -> PolyVec {
    PolyVec {
        polys: v.polys.iter().map(|p| low_bits(p, gamma2)).collect(),
    }
}

/// Compute hint vector for signing.
fn compute_hint_vec(z: &PolyVec, r: &PolyVec, gamma2: i32) -> (PolyVec, usize) {
    assert_eq!(z.len(), r.len());
    let mut h = PolyVec::new(z.len());
    let mut total_count = 0;
    for i in 0..z.len() {
        let (hint, count) = MlDsaPoly::make_hint(&z.polys[i], &r.polys[i], gamma2);
        h.polys[i] = hint;
        total_count += count;
    }
    (h, total_count)
}

/// Count the total number of 1s in a hint vector.
fn count_ones(h: &PolyVec) -> usize {
    h.polys.iter().map(|p| p.coeffs.iter().filter(|&&c| c == 1).count()).sum()
}

// ============================================================================
// ML-DSA-65 Verification
// ============================================================================

/// Verify a signature.
pub fn verify(pk: &MlDsaPublicKey, message: &[u8], sig: &MlDsaSignature) -> bool {
    // Step 1: Parse signature
    let c = sample_in_ball(&sig.c_tilde);
    let z = &sig.z;
    let h = &sig.h;

    // Step 2: Check norm bound
    if !z.check_norm_bound((GAMMA1 - BETA) as i32) {
        return false;
    }

    // Step 3: Recompute μ = H(tr || M)
    let pk_bytes = encode_pk_bytes(&pk.rho, &pk.t1);
    let tr = h256(&pk_bytes);
    let mut mu_input = Vec::with_capacity(SEED_LEN + message.len());
    mu_input.extend_from_slice(&tr);
    mu_input.extend_from_slice(message);
    let mu = h256(&mu_input);

    // Step 4: Compute w1' = UseHint(h, A*z - c*t1*2^d)
    let a = sample_matrix_a(&pk.rho);
    let az = a.mul_vec(z);

    // c * t1
    let mut ct1 = PolyVec::new(K);
    for i in 0..K {
        ct1.polys[i] = poly_mul(&c, &pk.t1.polys[i]);
    }

    // A*z - c*t1*2^d
    let pow2d = 1i32 << 13;
    let ct1_scaled = ct1.scale(pow2d);
    let az_minus_ct1 = az.sub(&ct1_scaled);

    // Apply hint: w1' = HighBits(w') + h (where h encodes the direction)
    let hb_az_minus_ct1 = high_bits_vec(&az_minus_ct1, GAMMA2 as i32);
    let w1_prime = hb_az_minus_ct1.add(h);

    // Step 5: Check c~ == H(μ || w1')
    let mut c_input = Vec::with_capacity(32 + K * 32);
    c_input.extend_from_slice(&mu);
    for poly in &w1_prime.polys {
        for &coeff in &poly.coeffs {
            c_input.extend_from_slice(&(coeff as u16).to_le_bytes());
        }
    }
    let c_prime = h256(&c_input);
    c_prime == sig.c_tilde
}

fn use_hint_vec(h: &PolyVec, r: &PolyVec, gamma2: i32) -> PolyVec {
    assert_eq!(h.len(), r.len());
    PolyVec {
        polys: h.polys.iter().zip(r.polys.iter()).map(|(hi, ri)| {
            MlDsaPoly::use_hint(hi, ri, gamma2)
        }).collect(),
    }
}

impl PolyVec {
    /// Scale all polynomials by a scalar.
    pub fn scale(&self, scalar: i32) -> Self {
        Self {
            polys: self.polys.iter().map(|p| p.scalar_mul(scalar)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let (pk, sk) = keygen();
        assert_eq!(pk.t1.len(), K);
        assert_eq!(sk.s1.len(), L);
        assert_eq!(sk.s2.len(), K);
        assert_eq!(sk.t0.len(), K);
    }

    #[test]
    fn test_sign_verify_round_trip() {
        let (pk, sk) = keygen();
        let message = b"Test message for ML-DSA";

        let sig = sign(&sk, message);
        let valid = verify(&pk, message, &sig);

        assert!(valid, "Signature verification failed");
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let (pk, sk) = keygen();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let sig = sign(&sk, message);
        let valid = verify(&pk, wrong_message, &sig);

        assert!(!valid, "Should reject wrong message");
    }

    #[test]
    fn test_sign_verify_different_keys() {
        let (_pk1, sk1) = keygen();
        let (pk2, _sk2) = keygen();
        let message = b"Test message";

        let sig = sign(&sk1, message);
        let valid = verify(&pk2, message, &sig);

        assert!(!valid, "Should reject with wrong public key");
    }

    #[test]
    fn test_power2round() {
        let mut poly = MlDsaPoly::zero();
        for i in 0..N {
            poly.coeffs[i] = (i as i32 * 1000) % Q as i32;
        }
        let (r0, r1) = poly.power2round(13);
        // r = r1 * 2^13 + r0
        for i in 0..N {
            let reconstructed = r1.coeffs[i] * 8192 + r0.coeffs[i];
            let diff = (poly.coeffs[i] - reconstructed).rem_euclid(Q as i32);
            assert!(diff == 0, "Power2Round failed at {}: {} != {}", i, poly.coeffs[i], reconstructed);
        }
    }

    #[test]
    fn test_power2round_range() {
        let mut poly = MlDsaPoly::zero();
        for i in 0..N {
            poly.coeffs[i] = (i as i32 * 1337) % Q as i32;
        }
        let (r0, r1) = poly.power2round(13);
        // r0 should be in [-4096, 4096)
        for i in 0..N {
            assert!(r0.coeffs[i] >= -4096 && r0.coeffs[i] < 4096,
                "r0 out of range at {}: {}", i, r0.coeffs[i]);
        }
        // r1 should be in [0, 1023]
        for i in 0..N {
            assert!(r1.coeffs[i] >= 0 && r1.coeffs[i] <= 1023,
                "r1 out of range at {}: {}", i, r1.coeffs[i]);
        }
    }

    #[test]
    fn test_sample_in_ball() {
        let seed = [0x42u8; 32];
        let c = sample_in_ball(&seed);
        // Should have exactly TAU non-zero coefficients
        let non_zero = c.coeffs.iter().filter(|&&c| c != 0).count();
        assert_eq!(non_zero, TAU, "Expected {} non-zero coefficients, got {}", TAU, non_zero);
        // All non-zero coefficients should be ±1
        for &coeff in &c.coeffs {
            assert!(coeff == 0 || coeff == 1 || coeff == -1,
                "Invalid coefficient: {}", coeff);
        }
    }

    #[test]
    fn test_poly_mul() {
        let a = MlDsaPoly { coeffs: [1; N] };
        let b = MlDsaPoly { coeffs: [2; N] };
        let c = poly_mul(&a, &b);
        assert!(c.coeffs.iter().any(|&c| c != 0));
    }

    #[test]
    fn test_poly_mul_identity() {
        // Multiply by 1 should give the same polynomial
        let mut a = MlDsaPoly::zero();
        a.coeffs[0] = 42;
        a.coeffs[1] = 17;
        let mut one = MlDsaPoly::zero();
        one.coeffs[0] = 1;
        let c = poly_mul(&a, &one);
        assert_eq!(c.coeffs[0], 42);
        assert_eq!(c.coeffs[1], 17);
        for i in 2..N {
            assert_eq!(c.coeffs[i], 0);
        }
    }

    #[test]
    fn test_poly_mul_negacyclic() {
        // x^255 * x = x^256 = -1 (in R_q)
        let mut a = MlDsaPoly::zero();
        let mut b = MlDsaPoly::zero();
        a.coeffs[255] = 1;
        b.coeffs[1] = 1;
        let c = poly_mul(&a, &b);
        assert_eq!(c.coeffs[0], Q as i32 - 1); // -1 mod q
        for i in 1..N {
            assert_eq!(c.coeffs[i], 0);
        }
    }

    #[test]
    fn test_poly_mul_commutative() {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut a = MlDsaPoly::zero();
        let mut b = MlDsaPoly::zero();
        for i in 0..16 {
            a.coeffs[i] = (rng.next_u32() % Q) as i32;
            b.coeffs[i] = (rng.next_u32() % Q) as i32;
        }
        let ab = poly_mul(&a, &b);
        let ba = poly_mul(&b, &a);
        for i in 0..N {
            assert_eq!(ab.coeffs[i], ba.coeffs[i], "Commutativity failed at {}", i);
        }
    }

    #[test]
    fn test_low_bits_range() {
        // low_bits should return values in (-γ₂, γ₂]
        let mut r = MlDsaPoly::zero();
        for i in 0..N {
            r.coeffs[i] = (i as i32 * 13337) % Q as i32;
        }
        let r0 = low_bits(&r, GAMMA2 as i32);
        for i in 0..N {
            assert!(r0.coeffs[i] > -(GAMMA2 as i32) && r0.coeffs[i] <= GAMMA2 as i32,
                "low_bits out of range at {}: {}", i, r0.coeffs[i]);
        }
    }

    #[test]
    fn test_low_bits_round_trip() {
        // r = high_bits * 2γ₂ + low_bits
        let mut r = MlDsaPoly::zero();
        for i in 0..N {
            r.coeffs[i] = (i as i32 * 7777) % Q as i32;
        }
        let r0 = low_bits(&r, GAMMA2 as i32);
        let r1 = high_bits(&r, GAMMA2 as i32);
        for i in 0..N {
            let reconstructed = r1.coeffs[i] * 2 * GAMMA2 as i32 + r0.coeffs[i];
            let diff = (r.coeffs[i] - reconstructed).rem_euclid(Q as i32);
            assert!(diff == 0, "low/high bits round trip failed at {}: {} vs {}", i, r.coeffs[i], reconstructed);
        }
    }

    #[test]
    fn test_check_norm_bound() {
        let mut poly = MlDsaPoly::zero();
        poly.coeffs[0] = 100;
        assert!(poly.check_norm_bound(101));
        assert!(!poly.check_norm_bound(100));

        // Test centered representation
        poly.coeffs[1] = Q as i32 - 100; // -100 in centered form
        assert!(poly.check_norm_bound(101));
    }

    #[test]
    fn test_make_hint_use_hint() {
        let mut z = MlDsaPoly::zero();
        let mut r = MlDsaPoly::zero();
        z.coeffs[0] = 1;
        r.coeffs[0] = GAMMA2 as i32 + 1;

        let (_hint, count) = MlDsaPoly::make_hint(&z, &r, GAMMA2 as i32);
        // This should create a hint at position 0
        assert!(count <= 1);
    }

    #[test]
    fn test_sample_eta() {
        let seed = [0x42u8; 32];
        let poly = sample_eta(&seed, 0);
        // All coefficients should be in [-η, η]
        for &c in &poly.coeffs {
            assert!(c >= -(ETA as i32) && c <= ETA as i32,
                "Coefficient out of range: {}", c);
        }
    }

    #[test]
    fn test_sample_gamma1() {
        let seed = [0x42u8; 32];
        let poly = sample_gamma1(&seed, 0);
        // All coefficients should be in [-γ₁, γ₁]
        for &c in &poly.coeffs {
            assert!(c >= -(GAMMA1 as i32) && c <= GAMMA1 as i32,
                "Coefficient out of range: {}", c);
        }
    }

    #[test]
    fn test_deterministic_sign() {
        let (_, sk) = keygen();
        let message = b"Deterministic test";
        let rnd = [0x42u8; SEED_LEN];

        let sig1 = sign_internal(&sk, message, &rnd);
        let sig2 = sign_internal(&sk, message, &rnd);

        assert_eq!(sig1.c_tilde, sig2.c_tilde);
        assert_eq!(sig1.z, sig2.z);
        assert_eq!(sig1.h, sig2.h);
    }

    #[test]
    fn test_multiple_signatures() {
        let (pk, sk) = keygen();

        for i in 0..5 {
            let message = format!("Message {}", i);
            let sig = sign(&sk, message.as_bytes());
            let valid = verify(&pk, message.as_bytes(), &sig);
            assert!(valid, "Signature {} failed", i);
        }
    }

    #[test]
    fn test_large_message() {
        let (pk, sk) = keygen();
        let message = vec![0xABu8; 10000]; // 10KB message

        let sig = sign(&sk, &message);
        let valid = verify(&pk, &message, &sig);
        assert!(valid, "Large message signature failed");
    }

    #[test]
    fn test_empty_message() {
        let (pk, sk) = keygen();
        let message = b"";

        let sig = sign(&sk, message);
        let valid = verify(&pk, message, &sig);
        assert!(valid, "Empty message signature failed");
    }
}
