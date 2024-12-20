#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

// EXPORTS
// ================================================================================================

pub use assembly::{
    self,
    ast::{Module, ModuleKind},
    diagnostics, Assembler, AssemblyError,
};
pub use processor::{
    crypto, execute, execute_iter, utils, AdviceInputs, AdviceProvider, AsmOpInfo, DefaultHost,
    ExecutionError, ExecutionTrace, Host, Kernel, MemAdviceProvider, Operation, Program,
    ProgramInfo, StackInputs, VmState, VmStateIterator, ZERO,
};
pub use prover::{
    math, prove, Digest, ExecutionProof, FieldExtension, HashFunction, InputError, Proof,
    ProvingOptions, StackOutputs, Word,
};
pub use verifier::{verify, VerificationError};

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;
