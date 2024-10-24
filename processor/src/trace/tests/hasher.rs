use alloc::vec::Vec;

use miden_air::trace::{
    chiplets::hasher::P1_COL_IDX, main_trace::MainTrace, AUX_TRACE_RAND_ELEMENTS,
};
use vm_core::{
    crypto::merkle::{MerkleStore, MerkleTree, NodeIndex},
    FieldElement,
};

use super::{
    build_trace_from_ops_with_inputs, rand_array, AdviceInputs, Felt, Operation, Word, ONE, ZERO,
};
use crate::StackInputs;

// SIBLING TABLE TESTS
// ================================================================================================

#[test]
#[allow(clippy::needless_range_loop)]
fn hasher_p1_mp_verify() {
    let (tree, _) = build_merkle_tree();
    let store = MerkleStore::from(&tree);
    let node = tree.get_node(NodeIndex::new(3, 1).unwrap()).unwrap();

    // build program inputs
    let mut init_stack = vec![];
    append_word(&mut init_stack, node.into());
    init_stack.extend_from_slice(&[3, 1]);
    append_word(&mut init_stack, tree.root().into());
    init_stack.reverse();
    let stack_inputs = StackInputs::try_from_ints(init_stack).unwrap();
    let advice_inputs = AdviceInputs::default().with_merkle_store(store);

    // build execution trace and extract the sibling table column from it
    let ops = vec![Operation::MpVerify(0)];
    let trace = build_trace_from_ops_with_inputs(ops, stack_inputs, advice_inputs);
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    // executing MPVERIFY does not affect the sibling table - so, all values in the column must be
    // ONE
    for i in 0..p1.len() {
        assert_eq!(ONE, p1[i]);
    }
}

#[test]
#[allow(clippy::needless_range_loop)]
fn hasher_p1_mr_update() {
    let (tree, _) = build_merkle_tree();
    let index = 5_u64;
    let old_node = tree.get_node(NodeIndex::new(3, index).unwrap()).unwrap();
    let new_node = init_leaf(11);
    let path = tree.get_path(NodeIndex::new(3, index).unwrap()).unwrap();

    // build program inputs
    let mut init_stack = vec![];
    append_word(&mut init_stack, old_node.into());
    init_stack.extend_from_slice(&[3, index]);
    append_word(&mut init_stack, tree.root().into());
    append_word(&mut init_stack, new_node);

    init_stack.reverse();
    let stack_inputs = StackInputs::try_from_ints(init_stack).unwrap();
    let store = MerkleStore::from(&tree);
    let advice_inputs = AdviceInputs::default().with_merkle_store(store);

    // build execution trace and extract the sibling table column from it
    let ops = vec![Operation::MrUpdate];
    let trace = build_trace_from_ops_with_inputs(ops, stack_inputs, advice_inputs);
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    let row_values = [
        SiblingTableRow::new(Felt::new(index), path[0].into()).to_value(&trace.main_trace, &alphas),
        SiblingTableRow::new(Felt::new(index >> 1), path[1].into())
            .to_value(&trace.main_trace, &alphas),
        SiblingTableRow::new(Felt::new(index >> 2), path[2].into())
            .to_value(&trace.main_trace, &alphas),
    ];

    // make sure the first entry is ONE
    let mut expected_value = ONE;
    assert_eq!(expected_value, p1[0]);

    // the running product does not change for the next 7 steps because the hasher computes the
    // hash of the SPAN block
    for i in 1..8 {
        assert_eq!(expected_value, p1[i]);
    }

    // on step 8, computations of the "old Merkle root" is started and the first sibling is added
    // to the table in the following row (step 9)
    expected_value *= row_values[0];
    assert_eq!(expected_value, p1[9]);

    // and then again for the next 6 steps the value remains the same
    for i in 10..16 {
        assert_eq!(expected_value, p1[i]);
    }

    // on step 15, the next sibling is added to the table in the following row (step 16)
    expected_value *= row_values[1];
    assert_eq!(expected_value, p1[16]);

    // and then again for the next 6 steps the value remains the same
    for i in 18..24 {
        assert_eq!(expected_value, p1[i]);
    }

    // on step 23, the last sibling is added to the table in the following row (step 24)
    expected_value *= row_values[2];
    assert_eq!(expected_value, p1[24]);

    // and then again for the next 7 steps the value remains the same
    for i in 25..33 {
        assert_eq!(expected_value, p1[i]);
    }

    // on step 32, computations of the "new Merkle root" is started and the first sibling is
    // removed from the table in the following row (step 33)
    expected_value *= row_values[0].inv();
    assert_eq!(expected_value, p1[33]);

    // then, for the next 6 steps the value remains the same
    for i in 33..40 {
        assert_eq!(expected_value, p1[i]);
    }

    // on step 39, the next sibling is removed from the table in the following row (step 40)
    expected_value *= row_values[1].inv();
    assert_eq!(expected_value, p1[40]);

    // and then again for the next 6 steps the value remains the same
    for i in 41..48 {
        assert_eq!(expected_value, p1[i]);
    }

    // on step 47, the last sibling is removed from the table in the following row (step 48)
    expected_value *= row_values[2].inv();
    assert_eq!(expected_value, p1[48]);

    // at this point the table should be empty again, and it should stay empty until the end
    assert_eq!(expected_value, ONE);
    for i in 50..p1.len() {
        assert_eq!(ONE, p1[i]);
    }
}

// HELPER STRUCTS, METHODS AND FUNCTIONS
// ================================================================================================

fn build_merkle_tree() -> (MerkleTree, Vec<Word>) {
    // build a Merkle tree
    let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
    (MerkleTree::new(leaves.clone()).unwrap(), leaves)
}

fn init_leaves(values: &[u64]) -> Vec<Word> {
    values.iter().map(|&v| init_leaf(v)).collect()
}

fn init_leaf(value: u64) -> Word {
    [Felt::new(value), ZERO, ZERO, ZERO]
}

fn append_word(target: &mut Vec<u64>, word: Word) {
    word.iter().rev().for_each(|v| target.push(v.as_int()));
}

/// Describes a single entry in the sibling table which consists of a tuple `(index, node)` where
/// index is the index of the node at its depth. For example, assume a leaf has index n. For the
/// leaf's parent the index will be n << 1. For the parent of the parent, the index will be
/// n << 2 etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiblingTableRow {
    index: Felt,
    sibling: Word,
}

impl SiblingTableRow {
    pub fn new(index: Felt, sibling: Word) -> Self {
        Self { index, sibling }
    }

    /// Reduces this row to a single field element in the field specified by E. This requires
    /// at least 6 alpha values.
    pub fn to_value<E: FieldElement<BaseField = Felt>>(
        &self,
        _main_trace: &MainTrace,
        alphas: &[E],
    ) -> E {
        // when the least significant bit of the index is 0, the sibling will be in the 3rd word
        // of the hasher state, and when the least significant bit is 1, it will be in the 2nd
        // word. we compute the value in this way to make constraint evaluation a bit easier since
        // we need to compute the 2nd and the 3rd word values for other purposes as well.
        let lsb = self.index.as_int() & 1;
        if lsb == 0 {
            alphas[0]
                + alphas[3].mul_base(self.index)
                + alphas[12].mul_base(self.sibling[0])
                + alphas[13].mul_base(self.sibling[1])
                + alphas[14].mul_base(self.sibling[2])
                + alphas[15].mul_base(self.sibling[3])
        } else {
            alphas[0]
                + alphas[3].mul_base(self.index)
                + alphas[8].mul_base(self.sibling[0])
                + alphas[9].mul_base(self.sibling[1])
                + alphas[10].mul_base(self.sibling[2])
                + alphas[11].mul_base(self.sibling[3])
        }
    }
}
