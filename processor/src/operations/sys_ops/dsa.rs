use alloc::vec::Vec;

#[cfg(feature = "std")]
use vm_core::crypto::hash::Rpo256;
use vm_core::{
    crypto::dsa::rpo_falcon512::{Polynomial, SecretKey},
    utils::Deserializable,
    Felt, Word,
};

use crate::ExecutionError;

/// Gets as input a vector containing a secret key, and a word representing a message and outputs a
/// vector of values to be pushed onto the advice stack.
/// The values are the ones required for a Falcon signature verification inside the VM and they are:
///
/// 1. The nonce represented as 8 field elements.
/// 2. The expanded public key represented as the coefficients of a polynomial of degree < 512.
/// 3. The signature represented as the coefficients of a polynomial of degree < 512.
/// 4. The product of the above two polynomials in the ring of polynomials with coefficients in the
///    Miden field.
///
/// # Errors
/// Will return an error if either:
/// - The secret key is malformed due to either incorrect length or failed decoding.
/// - The signature generation failed.
#[cfg(feature = "std")]
pub fn falcon_sign(sk: &[Felt], msg: Word) -> Result<Vec<Felt>, ExecutionError> {
    // Create the corresponding secret key
    let mut sk_bytes = Vec::with_capacity(sk.len());
    for element in sk {
        let value = element.as_int();
        if value > u8::MAX as u64 {
            return Err(ExecutionError::MalformedSignatureKey("RPO Falcon512"));
        }
        sk_bytes.push(value as u8);
    }

    let sk = SecretKey::read_from_bytes(&sk_bytes)
        .map_err(|_| ExecutionError::MalformedSignatureKey("RPO Falcon512"))?;

    // We can now generate the signature
    let sig = sk.sign(msg);

    // The signature is composed of a nonce and a polynomial s2

    // The nonce is represented as 8 field elements.
    let nonce = sig.nonce();

    // We convert the signature to a polynomial
    let s2 = sig.sig_poly();

    // We also need in the VM the expanded key corresponding to the public key the was provided
    // via the operand stack
    let h = sk.compute_pub_key_poly().0;

    // Lastly, for the probabilistic product routine that is part of the verification procedure,
    // we need to compute the product of the expanded key and the signature polynomial in
    // the ring of polynomials with coefficients in the Miden field.
    let pi = Polynomial::mul_modulo_p(&h, s2);

    // We now push the expanded key, the signature polynomial, and the product of the
    // expanded key and the signature polynomial to the advice stack. We also push
    // the challenge point at which the previous polynomials will be evaluated.
    // Finally, we push the nonce needed for the hash-to-point algorithm.

    let mut polynomials: Vec<Felt> =
        h.coefficients.iter().map(|a| Felt::from(a.value() as u32)).collect();
    polynomials.extend(s2.coefficients.iter().map(|a| Felt::from(a.value() as u32)));
    polynomials.extend(pi.iter().map(|a| Felt::new(*a)));

    let digest_polynomials = Rpo256::hash_elements(&polynomials);
    let challenge = (digest_polynomials[0], digest_polynomials[1]);

    let mut result: Vec<Felt> = vec![challenge.0, challenge.1];
    result.extend_from_slice(&polynomials);
    result.extend_from_slice(&nonce.to_elements());

    result.reverse();
    Ok(result)
}

#[cfg(not(feature = "std"))]
pub fn falcon_sign(_pk_sk: &[Felt], _msg: Word) -> Result<Vec<Felt>, ExecutionError> {
    Err(ExecutionError::FailedSignatureGeneration(
        "RPO Falcon512 signature generation is not available in no_std context",
    ))
}
