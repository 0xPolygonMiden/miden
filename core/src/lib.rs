#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

pub mod chiplets;
pub mod errors;

pub use ::crypto::{Word, EMPTY_WORD, ONE, WORD_SIZE, ZERO};
pub mod crypto {
    pub mod merkle {
        pub use ::crypto::merkle::{
            DefaultMerkleStore, EmptySubtreeRoots, InnerNodeInfo, MerkleError, MerklePath,
            MerkleStore, MerkleTree, Mmr, MmrPeaks, NodeIndex, PartialMerkleTree,
            RecordingMerkleStore, SimpleSmt, StoreNode, TieredSmt,
        };
    }

    pub mod hash {
        pub use ::crypto::hash::{
            blake::{Blake3Digest, Blake3_160, Blake3_192, Blake3_256},
            rpo::{Rpo256, RpoDigest},
            ElementHasher, Hasher,
        };
    }

    pub mod random {
        pub use crate::random::*;
    }
}

pub use math::{
    fields::{f64::BaseElement as Felt, QuadExtension},
    polynom, ExtensionOf, FieldElement, StarkField, ToElements,
};

mod program;
pub use program::{blocks as code_blocks, CodeBlockTable, Kernel, Program, ProgramInfo};

mod operations;
pub use operations::{
    AdviceExtractor, AdviceFunction, AdviceInjector, AssemblyOp, DebugOptions, Decorator,
    DecoratorIterator, DecoratorList, HostFunction, HostResult, Operation,
};

pub mod stack;
pub use stack::{StackInputs, StackOutputs};

// TODO: this should move to miden-crypto crate
mod random;

pub mod utils;

// TYPE ALIASES
// ================================================================================================

pub type StackTopState = [Felt; stack::STACK_TOP_SIZE];
