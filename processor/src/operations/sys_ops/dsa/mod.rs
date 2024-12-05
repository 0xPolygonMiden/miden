use alloc::vec::Vec;

use rpo_stark::generate_advice_inputs_signature;
use vm_core::{
    crypto::{
        dsa::{
            rpo_falcon512::{Polynomial, SecretKey},
            rpo_stark::{PublicInputs as StarkPublicInputs, SecretKey as StarkSecretKey},
        },
        hash::RpoDigest,
        merkle::MerkleStore,
    },
    utils::Deserializable,
    Felt, Word,
};

use crate::ExecutionError;

mod rpo_stark;

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
pub(crate) fn falcon_sign(sk: &[Felt], msg: Word) -> Result<SignatureData, ExecutionError> {
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

    // We now push the nonce, the expanded key, the signature polynomial, and the product of the
    // expanded key and the signature polynomial to the advice stack.
    let mut advice_stack: Vec<Felt> = nonce.to_elements().to_vec();
    advice_stack.extend(h.coefficients.iter().map(|a| Felt::from(a.value() as u32)));
    advice_stack.extend(s2.coefficients.iter().map(|a| Felt::from(a.value() as u32)));
    advice_stack.extend(pi.iter().map(|a| Felt::new(*a)));

    Ok(SignatureData {
        advice_stack,
        store: None,
        advice_map: None,
    })
}

#[cfg(not(feature = "std"))]
pub(crate) fn falcon_sign(_pk_sk: &[Felt], _msg: Word) -> Result<Vec<Felt>, ExecutionError> {
    Err(ExecutionError::FailedSignatureGeneration(
        "RPO Falcon512 signature generation is not available in no_std context",
    ))
}

/// Gets as input a vector containing a secret key, and a word representing a message and outputs:
///
/// 1. a vector of values to be pushed onto the advice stack.
/// 2. a Merkle store containing authentication paths.
/// 3. an advice map mapping digests to vector of values.
///
/// The above output makes up the needed data for verifying the RPO STARK-based signature
/// scheme inside the VM.
///
/// # Errors
/// Will return an error if:
/// - signature generation fails.
#[cfg(feature = "std")]
pub(crate) fn rpo_stark_sign(sk: &[Felt], msg: [Felt; 4]) -> Result<SignatureData, ExecutionError> {
    let sk = StarkSecretKey::from_word(
        TryInto::<[Felt; 4]>::try_into(sk).expect("conversion to Word should not fail"),
    );
    let pk = sk.compute_public_key();

    let signature = sk.sign(msg);
    let pub_inputs = StarkPublicInputs::new(pk.inner(), msg);
    let proof = signature.inner();

    let advice_data = generate_advice_inputs_signature(proof, pub_inputs);
    advice_data.map_err(|_e| {
        ExecutionError::FailedSignatureGeneration(
            "failed to generate RPO STARK-based signature scheme",
        )
    })
}

#[cfg(not(feature = "std"))]
pub(crate) fn rpo_stark_sign(sk: &[Felt], msg: [Felt; 4]) -> Result<SignatureData, ExecutionError> {
    Err(ExecutionError::FailedSignatureGeneration(
        "RPO STARK-based signature generation is not available in no_std context",
    ))
}

/// A data structure containing the advice data needed for the verification of a DSA in Miden VM.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SignatureData {
    pub advice_stack: Vec<Felt>,
    pub store: Option<MerkleStore>,
    pub advice_map: Option<Vec<(RpoDigest, Vec<Felt>)>>,
}
