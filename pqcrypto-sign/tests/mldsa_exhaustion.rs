use pqcrypto_sign::ml_dsa::{keygen, sign_internal};
use pqcrypto_sign::SignError;

#[test]
fn test_rejection_sampling_exhausted() {
    let (_pk, mut sk) = keygen();

    // Set s1 to have very large coefficients so that the check_norm_bound on z fails.
    // Specifically, we set all coefficients to Q / 2, which is around 4,190,208.
    // This will guarantee that z = y + c * s1 always has coefficients far out of bounds.
    for poly in &mut sk.s1.polys {
        for coeff in &mut poly.coeffs {
            *coeff = 4_000_000;
        }
    }

    let message = b"Exhaust rejection sampling test message";
    let rnd = [0u8; 32];

    let result = sign_internal(&sk, message, &rnd);
    assert!(
        matches!(result, Err(SignError::RejectionSamplingExhausted)),
        "Expected Err(RejectionSamplingExhausted), got {:?}",
        result
    );
}
