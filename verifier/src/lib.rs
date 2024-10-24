#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec;
use core::fmt;

use air::{HashFunction, ProcessorAir, ProvingOptions, PublicInputs};
use vm_core::crypto::{
    hash::{Blake3_192, Blake3_256, Rpo256, Rpx256},
    random::{RpoRandomCoin, RpxRandomCoin, WinterRandomCoin},
};
// EXPORTS
// ================================================================================================
pub use vm_core::{chiplets::hasher::Digest, Kernel, ProgramInfo, StackInputs, StackOutputs, Word};
use winter_verifier::{crypto::MerkleTree, verify as verify_proof};
pub use winter_verifier::{AcceptableOptions, VerifierError};
pub mod math {
    pub use vm_core::{Felt, FieldElement, StarkField};
}
pub use air::ExecutionProof;

// VERIFIER
// ================================================================================================
/// Returns the security level of the proof if the specified program was executed correctly against
/// the specified inputs and outputs.
///
/// Specifically, verifies that if a program with the specified `program_hash` is executed against
/// the provided `stack_inputs` and some secret inputs, the result is equal to the `stack_outputs`.
///
/// Stack inputs are expected to be ordered as if they would be pushed onto the stack one by one.
/// Thus, their expected order on the stack will be the reverse of the order in which they are
/// provided, and the last value in the `stack_inputs` slice is expected to be the value at the top
/// of the stack.
///
/// Stack outputs are expected to be ordered as if they would be popped off the stack one by one.
/// Thus, the value at the top of the stack is expected to be in the first position of the
/// `stack_outputs` slice, and the order of the rest of the output elements will also match the
/// order on the stack. This is the reverse of the order of the `stack_inputs` slice.
///
/// The verifier accepts proofs generated using a parameter set defined in [ProvingOptions].
/// Specifically, parameter sets targeting the following are accepted:
/// - 96-bit security level, non-recursive context (BLAKE3 hash function).
/// - 96-bit security level, recursive context (BLAKE3 hash function).
/// - 128-bit security level, non-recursive context (RPO hash function).
/// - 128-bit security level, recursive context (RPO hash function).
///
/// # Errors
/// Returns an error if:
/// - The provided proof does not prove a correct execution of the program.
/// - The protocol parameters used to generate the proof are not in the set of acceptable
///   parameters.
#[tracing::instrument("verify_program", skip_all)]
pub fn verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
) -> Result<u32, VerificationError> {
    // get security level of the proof
    let security_level = proof.security_level();

    // build public inputs and try to verify the proof
    let pub_inputs = PublicInputs::new(program_info, stack_inputs, stack_outputs);
    let (hash_fn, proof) = proof.into_parts();
    match hash_fn {
        HashFunction::Blake3_192 => {
            let opts = AcceptableOptions::OptionSet(vec![ProvingOptions::REGULAR_96_BITS]);
            verify_proof::<ProcessorAir, Blake3_192, WinterRandomCoin<_>, MerkleTree<_>>(
                proof, pub_inputs, &opts,
            )
        },
        HashFunction::Blake3_256 => {
            let opts = AcceptableOptions::OptionSet(vec![ProvingOptions::REGULAR_128_BITS]);
            verify_proof::<ProcessorAir, Blake3_256, WinterRandomCoin<_>, MerkleTree<_>>(
                proof, pub_inputs, &opts,
            )
        },
        HashFunction::Rpo256 => {
            let opts = AcceptableOptions::OptionSet(vec![
                ProvingOptions::RECURSIVE_96_BITS,
                ProvingOptions::RECURSIVE_128_BITS,
            ]);
            verify_proof::<ProcessorAir, Rpo256, RpoRandomCoin, MerkleTree<_>>(
                proof, pub_inputs, &opts,
            )
        },
        HashFunction::Rpx256 => {
            let opts = AcceptableOptions::OptionSet(vec![
                ProvingOptions::RECURSIVE_96_BITS,
                ProvingOptions::RECURSIVE_128_BITS,
            ]);
            verify_proof::<ProcessorAir, Rpx256, RpxRandomCoin, MerkleTree<_>>(
                proof, pub_inputs, &opts,
            )
        },
    }
    .map_err(VerificationError::VerifierError)?;

    Ok(security_level)
}

// ERRORS
// ================================================================================================

/// TODO: add docs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    VerifierError(VerifierError),
    InputNotFieldElement(u64),
    OutputNotFieldElement(u64),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use VerificationError::*;
        match self {
            VerifierError(e) => write!(f, "{e}"),
            InputNotFieldElement(i) => write!(f, "the input {i} is not a valid field element!"),
            OutputNotFieldElement(o) => write!(f, "the output {o} is not a valid field element!"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerificationError {}
