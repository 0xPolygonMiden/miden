use alloc::vec::Vec;

use vm_core::{
    crypto::{hash::RpoDigest, merkle::MerklePath},
    Felt,
};

use crate::{ExecutionError, ProcessState, Word};

mod inputs;
pub use inputs::AdviceInputs;

mod providers;
pub use providers::{MemAdviceProvider, RecAdviceProvider};

mod source;
pub use source::AdviceSource;

// ADVICE PROVIDER
// ================================================================================================

/// Defines behavior of an advice provider.
///
/// An advice provider is a component through which the host can interact with the advice provider.
/// The host can request nondeterministic inputs from the advice provider (i.e., result of a
/// computation performed outside of the VM), as well as insert new data into the advice provider.
///
/// An advice provider consists of the following components:
/// 1. Advice stack, which is a LIFO data structure. The processor can move the elements from the
///    advice stack onto the operand stack, as well as push new elements onto the advice stack.
/// 2. Advice map, which is a key-value map where keys are words (4 field elements) and values are
///    vectors of field elements. The processor can push the values from the map onto the advice
///    stack, as well as insert new values into the map.
/// 3. Merkle store, which contains structured data reducible to Merkle paths. The VM can request
///    Merkle paths from the store, as well as mutate it by updating or merging nodes contained in
///    the store.
pub trait AdviceProvider: Sized {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    // ADVICE STACK
    // --------------------------------------------------------------------------------------------

    /// Pops an element from the advice stack and returns it.
    ///
    /// # Errors
    /// Returns an error if the advice stack is empty.
    fn pop_stack(&mut self, process: ProcessState) -> Result<Felt, ExecutionError>;

    /// Pops a word (4 elements) from the advice stack and returns it.
    ///
    /// Note: a word is popped off the stack element-by-element. For example, a `[d, c, b, a, ...]`
    /// stack (i.e., `d` is at the top of the stack) will yield `[d, c, b, a]`.
    ///
    /// # Errors
    /// Returns an error if the advice stack does not contain a full word.
    fn pop_stack_word(&mut self, process: ProcessState) -> Result<Word, ExecutionError>;

    /// Pops a double word (8 elements) from the advice stack and returns them.
    ///
    /// Note: words are popped off the stack element-by-element. For example, a
    /// `[h, g, f, e, d, c, b, a, ...]` stack (i.e., `h` is at the top of the stack) will yield
    /// two words: `[h, g, f,e ], [d, c, b, a]`.
    ///
    /// # Errors
    /// Returns an error if the advice stack does not contain two words.
    fn pop_stack_dword(&mut self, process: ProcessState) -> Result<[Word; 2], ExecutionError>;

    /// Pushes the value(s) specified by the source onto the advice stack.
    ///
    /// # Errors
    /// Returns an error if the value specified by the advice source cannot be obtained.
    fn push_stack(&mut self, source: AdviceSource) -> Result<(), ExecutionError>;

    // ADVICE MAP
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the value(s) associated with the specified key in the advice map.
    fn get_mapped_values(&self, key: &RpoDigest) -> Option<&[Felt]>;

    /// Inserts the provided value into the advice map under the specified key.
    ///
    /// The values in the advice map can be moved onto the advice stack by invoking
    /// [AdviceProvider::push_stack()] method.
    ///
    /// If the specified key is already present in the advice map, the values under the key
    /// are replaced with the specified values.
    fn insert_into_map(&mut self, key: Word, values: Vec<Felt>);

    // MERKLE STORE
    // --------------------------------------------------------------------------------------------

    /// Returns a node at the specified depth and index in a Merkle tree with the given root.
    ///
    /// # Errors
    /// Returns an error if:
    /// - A Merkle tree for the specified root cannot be found in this advice provider.
    /// - The specified depth is either zero or greater than the depth of the Merkle tree identified
    ///   by the specified root.
    /// - Value of the node at the specified depth and index is not known to this advice provider.
    fn get_tree_node(&self, root: Word, depth: &Felt, index: &Felt)
        -> Result<Word, ExecutionError>;

    /// Returns a path to a node at the specified depth and index in a Merkle tree with the
    /// specified root.
    ///
    /// # Errors
    /// Returns an error if:
    /// - A Merkle tree for the specified root cannot be found in this advice provider.
    /// - The specified depth is either zero or greater than the depth of the Merkle tree identified
    ///   by the specified root.
    /// - Path to the node at the specified depth and index is not known to this advice provider.
    fn get_merkle_path(
        &self,
        root: Word,
        depth: &Felt,
        index: &Felt,
    ) -> Result<MerklePath, ExecutionError>;

    /// Reconstructs a path from the root until a leaf or empty node and returns its depth.
    ///
    /// For more information, check [crate::crypto::MerkleStore::get_leaf_depth].
    ///
    /// # Errors
    /// Will return an error if:
    /// - The provided `tree_depth` doesn't fit `u8`.
    /// - The conditions of [crate::crypto::MerkleStore::get_leaf_depth] aren't met.
    fn get_leaf_depth(
        &self,
        root: Word,
        tree_depth: &Felt,
        index: &Felt,
    ) -> Result<u8, ExecutionError>;

    /// Updates a node at the specified depth and index in a Merkle tree with the specified root;
    /// returns the Merkle path from the updated node to the new root, together with the new root.
    ///
    /// The tree is cloned prior to the update. Thus, the advice provider retains the original and
    /// the updated tree.
    ///
    /// # Errors
    /// Returns an error if:
    /// - A Merkle tree for the specified root cannot be found in this advice provider.
    /// - The specified depth is either zero or greater than the depth of the Merkle tree identified
    ///   by the specified root.
    /// - Path to the leaf at the specified index in the specified Merkle tree is not known to this
    ///   advice provider.
    fn update_merkle_node(
        &mut self,
        root: Word,
        depth: &Felt,
        index: &Felt,
        value: Word,
    ) -> Result<(MerklePath, Word), ExecutionError>;

    /// Creates a new Merkle tree in the advice provider by combining Merkle trees with the
    /// specified roots. The root of the new tree is defined as `hash(left_root, right_root)`.
    ///
    /// After the operation, both the original trees and the new tree remains in the advice
    /// provider (i.e., the input trees are not removed).
    ///
    /// It is not checked whether a Merkle tree for either of the specified roots can be found in
    /// this advice provider.
    fn merge_roots(&mut self, lhs: Word, rhs: Word) -> Result<Word, ExecutionError>;
}
