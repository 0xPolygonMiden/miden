use super::{
    super::{
        ExecutionOptions, ExecutionTrace, Felt, Kernel, Operation, Process, StackInputs, Word,
    },
    build_op_group,
};
use crate::DefaultHost;
use alloc::vec::Vec;
use miden_air::trace::{
    decoder::{
        ADDR_COL_IDX, GROUP_COUNT_COL_IDX, HASHER_STATE_RANGE, IN_SPAN_COL_IDX, NUM_HASHER_COLUMNS,
        NUM_OP_BATCH_FLAGS, NUM_OP_BITS, OP_BATCH_1_GROUPS, OP_BATCH_2_GROUPS, OP_BATCH_4_GROUPS,
        OP_BATCH_8_GROUPS, OP_BATCH_FLAGS_RANGE, OP_BITS_EXTRA_COLS_RANGE, OP_BITS_OFFSET,
        OP_INDEX_COL_IDX,
    },
    CTX_COL_IDX, DECODER_TRACE_RANGE, DECODER_TRACE_WIDTH, FMP_COL_IDX, FN_HASH_RANGE,
    IN_SYSCALL_COL_IDX, SYS_TRACE_RANGE, SYS_TRACE_WIDTH,
};
use test_utils::rand::rand_value;
use vm_core::{
    mast::{BasicBlockNode, Program, OP_BATCH_SIZE},
    MastForest, MastNode, MerkleTreeNode, EMPTY_WORD, ONE, ZERO,
};

// CONSTANTS
// ================================================================================================

const TWO: Felt = Felt::new(2);
const THREE: Felt = Felt::new(3);
const EIGHT: Felt = Felt::new(8);

const INIT_ADDR: Felt = ONE;
const FMP_MIN: Felt = Felt::new(crate::FMP_MIN);
const SYSCALL_FMP_MIN: Felt = Felt::new(crate::SYSCALL_FMP_MIN as u64);

// TYPE ALIASES
// ================================================================================================

type SystemTrace = [Vec<Felt>; SYS_TRACE_WIDTH];
type DecoderTrace = [Vec<Felt>; DECODER_TRACE_WIDTH];

// SPAN BLOCK TESTS
// ================================================================================================

#[test]
fn basic_block_one_group() {
    let ops = vec![Operation::Pad, Operation::Add, Operation::Mul];
    let basic_block = BasicBlockNode::new(ops.clone());
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_node = MastNode::Block(basic_block.clone());
        let basic_block_id = mast_forest.ensure_node(basic_block_node);
        mast_forest.set_entrypoint(basic_block_id);

        Program::new(mast_forest).unwrap()
    };

    let (trace, trace_len) = build_trace(&[], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Pad, 0, 0, 1);
    check_op_decoding(&trace, 2, INIT_ADDR, Operation::Add, 0, 1, 1);
    check_op_decoding(&trace, 3, INIT_ADDR, Operation::Mul, 0, 2, 1);
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 5, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------
    let program_hash: Word = program.entrypoint_digest().into();
    check_hasher_state(
        &trace,
        vec![
            basic_block.op_batches()[0].groups().to_vec(), // first group should contain op batch
            vec![build_op_group(&ops[1..])],
            vec![build_op_group(&ops[2..])],
            vec![],
            program_hash.to_vec(), // last row should contain program hash
        ],
    );

    // HALT opcode and program hash gets propagated to the last row
    for i in 6..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

#[test]
fn basic_block_small() {
    let iv = [ONE, TWO];
    let ops = vec![Operation::Push(iv[0]), Operation::Push(iv[1]), Operation::Add];
    let basic_block = BasicBlockNode::new(ops.clone());
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_node = MastNode::Block(basic_block.clone());
        let basic_block_id = mast_forest.ensure_node(basic_block_node);
        mast_forest.set_entrypoint(basic_block_id);

        Program::new(mast_forest).unwrap()
    };

    let (trace, trace_len) = build_trace(&[], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Span, 4, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Push(iv[0]), 3, 0, 1);
    check_op_decoding(&trace, 2, INIT_ADDR, Operation::Push(iv[1]), 2, 1, 1);
    check_op_decoding(&trace, 3, INIT_ADDR, Operation::Add, 1, 2, 1);
    // starting new group: NOOP group is inserted by the processor to make sure number of groups
    // is a power of two
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::Noop, 0, 0, 1);
    check_op_decoding(&trace, 5, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 6, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------
    let program_hash: Word = program.entrypoint_digest().into();
    check_hasher_state(
        &trace,
        vec![
            basic_block.op_batches()[0].groups().to_vec(),
            vec![build_op_group(&ops[1..])],
            vec![build_op_group(&ops[2..])],
            vec![],
            vec![],
            program_hash.to_vec(), // last row should contain program hash
        ],
    );

    // HALT opcode and program hash gets propagated to the last row
    for i in 7..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

#[test]
fn basic_block() {
    let iv = [ONE, TWO, Felt::new(3), Felt::new(4), Felt::new(5)];
    let ops = vec![
        Operation::Push(iv[0]),
        Operation::Push(iv[1]),
        Operation::Push(iv[2]),
        Operation::Pad,
        Operation::Mul,
        Operation::Add,
        Operation::Drop,
        Operation::Push(iv[3]),
        Operation::Push(iv[4]),
        Operation::Mul,
        Operation::Add,
        Operation::Inv,
    ];
    let basic_block = BasicBlockNode::new(ops.clone());
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_node = MastNode::Block(basic_block.clone());
        let basic_block_id = mast_forest.ensure_node(basic_block_node);
        mast_forest.set_entrypoint(basic_block_id);

        Program::new(mast_forest).unwrap()
    };
    let (trace, trace_len) = build_trace(&[], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Span, 8, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Push(iv[0]), 7, 0, 1);
    check_op_decoding(&trace, 2, INIT_ADDR, Operation::Push(iv[1]), 6, 1, 1);
    check_op_decoding(&trace, 3, INIT_ADDR, Operation::Push(iv[2]), 5, 2, 1);
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::Pad, 4, 3, 1);
    check_op_decoding(&trace, 5, INIT_ADDR, Operation::Mul, 4, 4, 1);
    check_op_decoding(&trace, 6, INIT_ADDR, Operation::Add, 4, 5, 1);
    check_op_decoding(&trace, 7, INIT_ADDR, Operation::Drop, 4, 6, 1);
    check_op_decoding(&trace, 8, INIT_ADDR, Operation::Push(iv[3]), 4, 7, 1);
    // NOOP inserted by the processor to make sure the group doesn't end with a PUSH
    check_op_decoding(&trace, 9, INIT_ADDR, Operation::Noop, 3, 8, 1);
    // starting new operation group
    check_op_decoding(&trace, 10, INIT_ADDR, Operation::Push(iv[4]), 2, 0, 1);
    check_op_decoding(&trace, 11, INIT_ADDR, Operation::Mul, 1, 1, 1);
    check_op_decoding(&trace, 12, INIT_ADDR, Operation::Add, 1, 2, 1);
    check_op_decoding(&trace, 13, INIT_ADDR, Operation::Inv, 1, 3, 1);
    // NOOP inserted by the processor to make sure the number of groups is a power of two
    check_op_decoding(&trace, 14, INIT_ADDR, Operation::Noop, 0, 0, 1);
    check_op_decoding(&trace, 15, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 16, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------
    let program_hash: Word = program.entrypoint_digest().into();
    check_hasher_state(
        &trace,
        vec![
            basic_block.op_batches()[0].groups().to_vec(),
            vec![build_op_group(&ops[1..8])], // first group starts
            vec![build_op_group(&ops[2..8])],
            vec![build_op_group(&ops[3..8])],
            vec![build_op_group(&ops[4..8])],
            vec![build_op_group(&ops[5..8])],
            vec![build_op_group(&ops[6..8])],
            vec![build_op_group(&ops[7..8])],
            vec![], // NOOP inserted after push
            vec![],
            vec![build_op_group(&ops[9..])], // next group starts
            vec![build_op_group(&ops[10..])],
            vec![build_op_group(&ops[11..])],
            vec![],
            vec![],                // a group with single NOOP added at the end
            program_hash.to_vec(), // last row should contain program hash
        ],
    );

    // HALT opcode and program hash gets propagated to the last row
    for i in 17..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

#[test]
fn span_block_with_respan() {
    let iv = [
        ONE,
        TWO,
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        Felt::new(7),
        EIGHT,
        Felt::new(9),
    ];

    let ops = vec![
        Operation::Push(iv[0]),
        Operation::Push(iv[1]),
        Operation::Push(iv[2]),
        Operation::Push(iv[3]),
        Operation::Push(iv[4]),
        Operation::Push(iv[5]),
        Operation::Push(iv[6]),
        Operation::Push(iv[7]),
        Operation::Add,
        Operation::Push(iv[8]),
    ];
    let basic_block = BasicBlockNode::new(ops.clone());
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_node = MastNode::Block(basic_block.clone());
        let basic_block_id = mast_forest.ensure_node(basic_block_node);
        mast_forest.set_entrypoint(basic_block_id);

        Program::new(mast_forest).unwrap()
    };
    let (trace, trace_len) = build_trace(&[], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Span, 12, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Push(iv[0]), 11, 0, 1);
    check_op_decoding(&trace, 2, INIT_ADDR, Operation::Push(iv[1]), 10, 1, 1);
    check_op_decoding(&trace, 3, INIT_ADDR, Operation::Push(iv[2]), 9, 2, 1);
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::Push(iv[3]), 8, 3, 1);
    check_op_decoding(&trace, 5, INIT_ADDR, Operation::Push(iv[4]), 7, 4, 1);
    check_op_decoding(&trace, 6, INIT_ADDR, Operation::Push(iv[5]), 6, 5, 1);
    check_op_decoding(&trace, 7, INIT_ADDR, Operation::Push(iv[6]), 5, 6, 1);
    // NOOP inserted by the processor to make sure the group doesn't end with a PUSH
    check_op_decoding(&trace, 8, INIT_ADDR, Operation::Noop, 4, 7, 1);
    // RESPAN since the previous batch is full
    let batch1_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&trace, 9, INIT_ADDR, Operation::Respan, 4, 0, 0);
    check_op_decoding(&trace, 10, batch1_addr, Operation::Push(iv[7]), 3, 0, 1);
    check_op_decoding(&trace, 11, batch1_addr, Operation::Add, 2, 1, 1);
    check_op_decoding(&trace, 12, batch1_addr, Operation::Push(iv[8]), 2, 2, 1);
    // NOOP inserted by the processor to make sure the group doesn't end with a PUSH
    check_op_decoding(&trace, 13, batch1_addr, Operation::Noop, 1, 3, 1);
    // NOOP inserted by the processor to make sure the number of groups is a power of two
    check_op_decoding(&trace, 14, batch1_addr, Operation::Noop, 0, 0, 1);
    check_op_decoding(&trace, 15, batch1_addr, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 16, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------
    let program_hash: Word = program.entrypoint_digest().into();
    check_hasher_state(
        &trace,
        vec![
            basic_block.op_batches()[0].groups().to_vec(),
            vec![build_op_group(&ops[1..7])], // first group starts
            vec![build_op_group(&ops[2..7])],
            vec![build_op_group(&ops[3..7])],
            vec![build_op_group(&ops[4..7])],
            vec![build_op_group(&ops[5..7])],
            vec![build_op_group(&ops[6..7])],
            vec![],
            vec![], // a NOOP inserted after last PUSH
            basic_block.op_batches()[1].groups().to_vec(),
            vec![build_op_group(&ops[8..])], // next group starts
            vec![build_op_group(&ops[9..])],
            vec![],
            vec![],                // a NOOP is inserted after last PUSH
            vec![],                // a group with single NOOP added at the end
            program_hash.to_vec(), // last row should contain program hash
        ],
    );

    // HALT opcode and program hash gets propagated to the last row
    for i in 17..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

// JOIN BLOCK TESTS
// ================================================================================================

#[test]
fn join_node() {
    let basic_block1 = MastNode::new_basic_block(vec![Operation::Mul]);
    let basic_block2 = MastNode::new_basic_block(vec![Operation::Add]);
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block1_id = mast_forest.ensure_node(basic_block1.clone());
        let basic_block2_id = mast_forest.ensure_node(basic_block2.clone());

        let join_node = MastNode::new_join(basic_block1_id, basic_block2_id, &mast_forest);
        let join_node_id = mast_forest.ensure_node(join_node);
        mast_forest.set_entrypoint(join_node_id);

        Program::new(mast_forest).unwrap()
    };

    let (trace, trace_len) = build_trace(&[], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Join, 0, 0, 0);
    // starting first span
    let span1_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 2, span1_addr, Operation::Mul, 0, 0, 1);
    check_op_decoding(&trace, 3, span1_addr, Operation::End, 0, 0, 0);
    // starting second span
    let span2_addr = INIT_ADDR + Felt::new(16);
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 5, span2_addr, Operation::Add, 0, 0, 1);
    check_op_decoding(&trace, 6, span2_addr, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 7, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 8, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to hashes of both child nodes
    let span1_hash: Word = basic_block1.digest().into();
    let span2_hash: Word = basic_block2.digest().into();
    assert_eq!(span1_hash, get_hasher_state1(&trace, 0));
    assert_eq!(span2_hash, get_hasher_state2(&trace, 0));

    // at the end of the first SPAN, the hasher state is set to the hash of the first child
    assert_eq!(span1_hash, get_hasher_state1(&trace, 3));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 3));

    // at the end of the second SPAN, the hasher state is set to the hash of the second child
    assert_eq!(span2_hash, get_hasher_state1(&trace, 6));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 6));

    // at the end of the program, the hasher state is set to the hash of the entire program
    let program_hash: Word = program.entrypoint_digest().into();
    assert_eq!(program_hash, get_hasher_state1(&trace, 7));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 7));

    // HALT opcode and program hash gets propagated to the last row
    for i in 9..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

// SPLIT BLOCK TESTS
// ================================================================================================

#[test]
fn split_node_true() {
    let basic_block1 = MastNode::new_basic_block(vec![Operation::Mul]);
    let basic_block2 = MastNode::new_basic_block(vec![Operation::Add]);
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block1_id = mast_forest.ensure_node(basic_block1.clone());
        let basic_block2_id = mast_forest.ensure_node(basic_block2.clone());

        let split_node = MastNode::new_split(basic_block1_id, basic_block2_id, &mast_forest);
        let split_node_id = mast_forest.ensure_node(split_node);
        mast_forest.set_entrypoint(split_node_id);

        Program::new(mast_forest).unwrap()
    };

    let (trace, trace_len) = build_trace(&[1], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    let basic_block_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&trace, 0, ZERO, Operation::Split, 0, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 2, basic_block_addr, Operation::Mul, 0, 0, 1);
    check_op_decoding(&trace, 3, basic_block_addr, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 5, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to hashes of both child nodes
    let span1_hash: Word = basic_block1.digest().into();
    let span2_hash: Word = basic_block2.digest().into();
    assert_eq!(span1_hash, get_hasher_state1(&trace, 0));
    assert_eq!(span2_hash, get_hasher_state2(&trace, 0));

    // at the end of the SPAN, the hasher state is set to the hash of the first child
    assert_eq!(span1_hash, get_hasher_state1(&trace, 3));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 3));

    // at the end of the program, the hasher state is set to the hash of the entire program
    let program_hash: Word = program.entrypoint_digest().into();
    assert_eq!(program_hash, get_hasher_state1(&trace, 4));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 4));

    // HALT opcode and program hash gets propagated to the last row
    for i in 6..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

#[test]
fn split_node_false() {
    let basic_block1 = MastNode::new_basic_block(vec![Operation::Mul]);
    let basic_block2 = MastNode::new_basic_block(vec![Operation::Add]);
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block1_id = mast_forest.ensure_node(basic_block1.clone());
        let basic_block2_id = mast_forest.ensure_node(basic_block2.clone());

        let split_node = MastNode::new_split(basic_block1_id, basic_block2_id, &mast_forest);
        let split_node_id = mast_forest.ensure_node(split_node);
        mast_forest.set_entrypoint(split_node_id);

        Program::new(mast_forest).unwrap()
    };

    let (trace, trace_len) = build_trace(&[0], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    let basic_block_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&trace, 0, ZERO, Operation::Split, 0, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 2, basic_block_addr, Operation::Add, 0, 0, 1);
    check_op_decoding(&trace, 3, basic_block_addr, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 5, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to hashes of both child nodes
    let span1_hash: Word = basic_block1.digest().into();
    let span2_hash: Word = basic_block2.digest().into();
    assert_eq!(span1_hash, get_hasher_state1(&trace, 0));
    assert_eq!(span2_hash, get_hasher_state2(&trace, 0));

    // at the end of the SPAN, the hasher state is set to the hash of the second child
    assert_eq!(span2_hash, get_hasher_state1(&trace, 3));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 3));

    // at the end of the program, the hasher state is set to the hash of the entire program
    let program_hash: Word = program.entrypoint_digest().into();
    assert_eq!(program_hash, get_hasher_state1(&trace, 4));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 4));

    // HALT opcode and program hash gets propagated to the last row
    for i in 6..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

// LOOP BLOCK TESTS
// ================================================================================================

#[test]
fn loop_node() {
    let loop_body = MastNode::new_basic_block(vec![Operation::Pad, Operation::Drop]);
    let program = {
        let mut mast_forest = MastForest::new();

        let loop_body_id = mast_forest.ensure_node(loop_body.clone());

        let loop_node = MastNode::new_loop(loop_body_id, &mast_forest);
        let loop_node_id = mast_forest.ensure_node(loop_node);
        mast_forest.set_entrypoint(loop_node_id);

        Program::new(mast_forest).unwrap()
    };

    let (trace, trace_len) = build_trace(&[0, 1], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    let body_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&trace, 0, ZERO, Operation::Loop, 0, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 2, body_addr, Operation::Pad, 0, 0, 1);
    check_op_decoding(&trace, 3, body_addr, Operation::Drop, 0, 1, 1);
    check_op_decoding(&trace, 4, body_addr, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 5, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 6, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to the hash of the loop's body
    let loop_body_hash: Word = loop_body.digest().into();
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 0));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 0));

    // at the end of the SPAN block, the hasher state is also set to the hash of the loops body,
    // and is_loop_body flag is also set to ONE
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 4));
    assert_eq!([ONE, ZERO, ZERO, ZERO], get_hasher_state2(&trace, 4));

    // the hash of the program is located in the last END row; this row should also have is_loop
    // flag set to ONE
    let program_hash: Word = program.entrypoint_digest().into();
    assert_eq!(program_hash, get_hasher_state1(&trace, 5));
    assert_eq!([ZERO, ONE, ZERO, ZERO], get_hasher_state2(&trace, 5));

    // HALT opcode and program hash gets propagated to the last row
    for i in 7..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

#[test]
fn loop_node_skip() {
    let loop_body = MastNode::new_basic_block(vec![Operation::Pad, Operation::Drop]);
    let program = {
        let mut mast_forest = MastForest::new();

        let loop_body_id = mast_forest.ensure_node(loop_body.clone());

        let loop_node = MastNode::new_loop(loop_body_id, &mast_forest);
        let loop_node_id = mast_forest.ensure_node(loop_node);
        mast_forest.set_entrypoint(loop_node_id);

        Program::new(mast_forest).unwrap()
    };

    let (trace, trace_len) = build_trace(&[0], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Loop, 0, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 2, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to the hash of the loop's body
    let loop_body_hash: Word = loop_body.digest().into();
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 0));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 0));

    // the hash of the program is located in the last END row; is_loop is not set to ONE because
    // we didn't enter the loop's body
    let program_hash: Word = program.entrypoint_digest().into();
    assert_eq!(program_hash, get_hasher_state1(&trace, 1));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 1));

    // HALT opcode and program hash gets propagated to the last row
    for i in 3..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

#[test]
fn loop_node_repeat() {
    let loop_body = MastNode::new_basic_block(vec![Operation::Pad, Operation::Drop]);
    let program = {
        let mut mast_forest = MastForest::new();

        let loop_body_id = mast_forest.ensure_node(loop_body.clone());

        let loop_node = MastNode::new_loop(loop_body_id, &mast_forest);
        let loop_node_id = mast_forest.ensure_node(loop_node);
        mast_forest.set_entrypoint(loop_node_id);

        Program::new(mast_forest).unwrap()
    };

    let (trace, trace_len) = build_trace(&[0, 1, 1], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    let iter1_addr = INIT_ADDR + EIGHT;
    let iter2_addr = INIT_ADDR + Felt::new(16);

    check_op_decoding(&trace, 0, ZERO, Operation::Loop, 0, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 2, iter1_addr, Operation::Pad, 0, 0, 1);
    check_op_decoding(&trace, 3, iter1_addr, Operation::Drop, 0, 1, 1);
    check_op_decoding(&trace, 4, iter1_addr, Operation::End, 0, 0, 0);
    // start second iteration
    check_op_decoding(&trace, 5, INIT_ADDR, Operation::Repeat, 0, 0, 0);
    check_op_decoding(&trace, 6, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 7, iter2_addr, Operation::Pad, 0, 0, 1);
    check_op_decoding(&trace, 8, iter2_addr, Operation::Drop, 0, 1, 1);
    check_op_decoding(&trace, 9, iter2_addr, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 10, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 11, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to the hash of the loop's body
    let loop_body_hash: Word = loop_body.digest().into();
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 0));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 0));

    // at the end of the first iteration, the hasher state is also set to the hash of the loops
    // body, and is_loop_body flag is also set to ONE
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 4));
    assert_eq!([ONE, ZERO, ZERO, ZERO], get_hasher_state2(&trace, 4));

    // at the RESPAN row hasher state is copied over from the previous row
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 5));
    assert_eq!([ONE, ZERO, ZERO, ZERO], get_hasher_state2(&trace, 5));

    // at the end of the second iteration, the hasher state is again set to the hash of the loops
    // body, and is_loop_body flag is also set to ONE
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 9));
    assert_eq!([ONE, ZERO, ZERO, ZERO], get_hasher_state2(&trace, 9));

    // the hash of the program is located in the last END row; this row should also have is_loop
    // flag set to ONE
    let program_hash: Word = program.entrypoint_digest().into();
    assert_eq!(program_hash, get_hasher_state1(&trace, 10));
    assert_eq!([ZERO, ONE, ZERO, ZERO], get_hasher_state2(&trace, 10));

    // HALT opcode and program hash gets propagated to the last row
    for i in 12..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

// CALL BLOCK TESTS
// ================================================================================================

#[test]
#[rustfmt::skip]
fn call_block() {
    // build a program which looks like this:
    //
    // proc.foo
    //     fmp <- fmp + 1
    // end
    //
    // begin
    //    fmp <- fmp + 2
    //    call.foo
    //    stack[0] <- fmp
    // end

    let mut mast_forest = MastForest::new();

    let first_basic_block = MastNode::new_basic_block(vec![
        Operation::Push(TWO),
        Operation::FmpUpdate,
        Operation::Pad,
    ]);
    let first_basic_block_id = mast_forest.ensure_node(first_basic_block.clone());

    let foo_root_node = MastNode::new_basic_block(vec![
        Operation::Push(ONE), Operation::FmpUpdate
    ]);
    let foo_root_node_id = mast_forest.ensure_node(foo_root_node.clone());

    let last_basic_block = MastNode::new_basic_block(vec![Operation::FmpAdd]);
    let last_basic_block_id = mast_forest.ensure_node(last_basic_block.clone());

    let foo_call_node = MastNode::new_call(foo_root_node_id, &mast_forest);
    let foo_call_node_id = mast_forest.ensure_node(foo_call_node.clone());

    let join1_node = MastNode::new_join(first_basic_block_id, foo_call_node_id, &mast_forest);
    let join1_node_id = mast_forest.ensure_node(join1_node.clone());

    let program_root = MastNode::new_join(join1_node_id, last_basic_block_id, &mast_forest);
    let program_root_id = mast_forest.ensure_node(program_root);
    mast_forest.set_entrypoint(program_root_id);

    let program = Program::new(mast_forest).unwrap();

    let (sys_trace, dec_trace,   trace_len) =
        build_call_trace(&program, Kernel::default());

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&dec_trace, 0, ZERO, Operation::Join, 0, 0, 0);
    // starting the internal JOIN block
    let join1_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&dec_trace, 1, INIT_ADDR, Operation::Join, 0, 0, 0);
    // starting first SPAN block
    let first_basic_block_addr = join1_addr + EIGHT;
    check_op_decoding(&dec_trace, 2, join1_addr, Operation::Span, 2, 0, 0);
    check_op_decoding(&dec_trace, 3, first_basic_block_addr, Operation::Push(TWO), 1, 0, 1);
    check_op_decoding(&dec_trace, 4, first_basic_block_addr, Operation::FmpUpdate, 0, 1, 1);
    check_op_decoding(&dec_trace, 5, first_basic_block_addr, Operation::Pad, 0, 2, 1);
    check_op_decoding(&dec_trace, 6, first_basic_block_addr, Operation::End, 0, 0, 0);
    // starting CALL block
    let foo_call_addr = first_basic_block_addr + EIGHT;
    check_op_decoding(&dec_trace, 7, join1_addr, Operation::Call, 0, 0, 0);
    // starting second SPAN block
    let foo_root_addr = foo_call_addr + EIGHT;
    check_op_decoding(&dec_trace, 8, foo_call_addr, Operation::Span, 2, 0, 0);
    check_op_decoding(&dec_trace, 9, foo_root_addr, Operation::Push(ONE), 1, 0, 1);
    check_op_decoding(&dec_trace, 10, foo_root_addr, Operation::FmpUpdate, 0, 1, 1);
    check_op_decoding(&dec_trace, 11, foo_root_addr, Operation::End, 0, 0, 0);
    // ending CALL block
    check_op_decoding(&dec_trace, 12, foo_call_addr, Operation::End, 0, 0, 0);
    // ending internal JOIN block
    check_op_decoding(&dec_trace, 13, join1_addr, Operation::End, 0, 0, 0);
    // starting the 3rd SPAN block
    let last_basic_block_addr = foo_root_addr + EIGHT;
    check_op_decoding(&dec_trace, 14, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&dec_trace, 15, last_basic_block_addr, Operation::FmpAdd, 0, 0, 1);
    check_op_decoding(&dec_trace, 16, last_basic_block_addr, Operation::End, 0, 0, 0);
    // ending the program
    check_op_decoding(&dec_trace, 17, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&dec_trace, 18, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------
    // in the first row, the hasher state is set to hashes of (join1, span3)
    let join1_hash: Word = join1_node.digest().into();
    let last_basic_block_hash: Word = last_basic_block.digest().into();
    assert_eq!(join1_hash, get_hasher_state1(&dec_trace, 0));
    assert_eq!(last_basic_block_hash, get_hasher_state2(&dec_trace, 0));

    // in the second row, the hasher state is set to hashes of (span1, fn_block)
    let first_span_hash: Word = first_basic_block.digest().into();
    let foo_call_hash: Word = foo_call_node.digest().into();
    assert_eq!(first_span_hash, get_hasher_state1(&dec_trace, 1));
    assert_eq!(foo_call_hash, get_hasher_state2(&dec_trace, 1));

    // at the end of the first SPAN, the hasher state is set to the hash of the first child
    assert_eq!(first_span_hash, get_hasher_state1(&dec_trace, 6));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 6));

    // in the 7th row, we start the CALL block which has basic_block2 as its only child
    let foo_root_hash: Word = foo_root_node.digest().into();
    assert_eq!(foo_root_hash, get_hasher_state1(&dec_trace, 7));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 7));

    // span2 ends in the 11th row
    assert_eq!(foo_root_hash, get_hasher_state1(&dec_trace, 11));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 11));

    // CALL block ends in the 12th row; the second to last element of the hasher state
    // is set to ONE because we are exiting the CALL block
    assert_eq!(foo_call_hash, get_hasher_state1(&dec_trace, 12));
    assert_eq!([ZERO, ZERO, ONE, ZERO], get_hasher_state2(&dec_trace, 12));

    // internal JOIN block ends in the 13th row
    assert_eq!(join1_hash, get_hasher_state1(&dec_trace, 13));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 13));

    // span3 ends in the 14th row
    assert_eq!(last_basic_block_hash, get_hasher_state1(&dec_trace, 16));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 16));

    // the program ends in the 17th row
    let program_hash: Word = program.entrypoint_digest().into();
    assert_eq!(program_hash, get_hasher_state1(&dec_trace, 17));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 17));

    // HALT opcode and program hash gets propagated to the last row
    for i in 18..trace_len {
        assert!(contains_op(&dec_trace, i, Operation::Halt));
        assert_eq!(ZERO, dec_trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, dec_trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&dec_trace, i));
    }

    // --- check the ctx column -------------------------------------------------------------------

    // for the first 7 cycles, we are in the root context
    for i in 0..8 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], ZERO);
    }

    // when CALL operation is executed, we switch to the new context
    for i in 8..13 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], EIGHT);
    }

    // once the CALL block exited, we go back to the root context
    for i in 13..trace_len {
        assert_eq!(sys_trace[CTX_COL_IDX][i], ZERO);
    }

    // --- check the fmp column -------------------------------------------------------------------

    // for the first 5 cycles fmp stays at initial value
    for i in 0..5 {
        assert_eq!(sys_trace[FMP_COL_IDX][i], FMP_MIN);
    }

    // when the first FmpUpdate is executed, fmp gets gets incremented by 2
    for i in 5..8 {
        assert_eq!(sys_trace[FMP_COL_IDX][i], FMP_MIN + TWO);
    }

    // when CALL operation is executed, fmp gets reset to the initial value
    for i in 8..11 {
        assert_eq!(sys_trace[FMP_COL_IDX][i], FMP_MIN);
    }

    // when the second FmpUpdate is executed, fmp gets gets incremented by 1
    for i in 11..13 {
        assert_eq!(sys_trace[FMP_COL_IDX][i], FMP_MIN + ONE);
    }

    // once the CALL block exited, fmp gets reset back to FMP_MIN + 2, and it remains unchanged
    // until the end of the trace
    for i in 13..trace_len {
        assert_eq!(sys_trace[FMP_COL_IDX][i], FMP_MIN + TWO);
    }

    // --- check the in_syscall column ------------------------------------------------------------

    // since no syscalls were made, values in the syscall flag column should be all ZEROs
    assert_eq!(
        &sys_trace[IN_SYSCALL_COL_IDX][..trace_len],
        vec![ZERO; trace_len]
    );

    // --- check fn hash columns ------------------------------------------------------------------

    // before the CALL operation is executed, we are in a root context and thus fn_hash is ZEROs.
    for i in 0..8 {
        assert_eq!(get_fn_hash(&sys_trace, i), EMPTY_WORD);
    }

    // inside the CALL block fn hash is set to the hash of the foo procedure
    for i in 8..13 {
        assert_eq!(get_fn_hash(&sys_trace, i), foo_root_hash);
    }

    // after the CALL block is ended, we are back in the root context
    for i in 13..trace_len {
        assert_eq!(get_fn_hash(&sys_trace, i), EMPTY_WORD);
    }
}

// SYSCALL BLOCK TESTS
// ================================================================================================

#[test]
#[rustfmt::skip]
fn syscall_block() {
    // build a program which looks like this:
    //
    // --- kernel ---
    // export.foo
    //     fmp <- fmp + 3
    // end
    //
    // --- program ---
    // proc.bar
    //     fmp <- fmp + 2
    //     syscall.foo
    // end
    //
    // begin
    //    fmp <- fmp + 1
    //    syscall.bar
    //    stack[0] <- fmp
    // end

    let mut mast_forest = MastForest::new();

    // build foo procedure body
    let foo_root = MastNode::new_basic_block(vec![Operation::Push(THREE), Operation::FmpUpdate]);
    let foo_root_id = mast_forest.ensure_node(foo_root.clone());
    let kernel = Kernel::new(&[foo_root.digest()]).unwrap();
    mast_forest.set_kernel(kernel.clone());

    // build bar procedure body
    let bar_basic_block = MastNode::new_basic_block(vec![Operation::Push(TWO), Operation::FmpUpdate]);
    let bar_basic_block_id = mast_forest.ensure_node(bar_basic_block.clone());

    let foo_call_node = MastNode::new_syscall(foo_root_id, &mast_forest);
    let foo_call_node_id = mast_forest.ensure_node(foo_call_node.clone());

    let bar_root_node = MastNode::new_join(bar_basic_block_id, foo_call_node_id, &mast_forest);
    let bar_root_node_id = mast_forest.ensure_node(bar_root_node.clone());

    // build the program
    let first_basic_block = MastNode::new_basic_block(vec![
        Operation::Push(ONE),
        Operation::FmpUpdate,
        Operation::Pad,
    ]);
    let first_basic_block_id = mast_forest.ensure_node(first_basic_block.clone());

    let last_basic_block = MastNode::new_basic_block(vec![Operation::FmpAdd]);
    let last_basic_block_id = mast_forest.ensure_node(last_basic_block.clone());

    let bar_call_node = MastNode::new_call(bar_root_node_id, &mast_forest);
    let bar_call_node_id = mast_forest.ensure_node(bar_call_node.clone());

    let inner_join_node = MastNode::new_join(first_basic_block_id, bar_call_node_id, &mast_forest);
    let inner_join_node_id = mast_forest.ensure_node(inner_join_node.clone());

    let program_root_node = MastNode::new_join(inner_join_node_id, last_basic_block_id, &mast_forest);
    let program_root_node_id = mast_forest.ensure_node(program_root_node.clone());
    mast_forest.set_entrypoint(program_root_node_id);

    let program = Program::new(mast_forest).unwrap();

    let (sys_trace, dec_trace,   trace_len) =
        build_call_trace(&program, kernel);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&dec_trace, 0, ZERO, Operation::Join, 0, 0, 0);
    // starting the internal JOIN block
    let inner_join_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&dec_trace, 1, INIT_ADDR, Operation::Join, 0, 0, 0);
    // starting first SPAN block
    let first_basic_block_addr = inner_join_addr + EIGHT;
    check_op_decoding(&dec_trace, 2, inner_join_addr, Operation::Span, 2, 0, 0);
    check_op_decoding(&dec_trace, 3, first_basic_block_addr, Operation::Push(TWO), 1, 0, 1);
    check_op_decoding(&dec_trace, 4, first_basic_block_addr, Operation::FmpUpdate, 0, 1, 1);
    check_op_decoding(&dec_trace, 5, first_basic_block_addr, Operation::Pad, 0, 2, 1);
    check_op_decoding(&dec_trace, 6, first_basic_block_addr, Operation::End, 0, 0, 0);

    // starting CALL block for bar
    let call_addr = first_basic_block_addr + EIGHT;
    check_op_decoding(&dec_trace, 7, inner_join_addr, Operation::Call, 0, 0, 0);
    // starting JOIN block inside bar
    let bar_join_addr = call_addr + EIGHT;
    check_op_decoding(&dec_trace, 8, call_addr, Operation::Join, 0, 0, 0);
    // starting SPAN block inside bar
    let bar_basic_block_addr = bar_join_addr + EIGHT;
    check_op_decoding(&dec_trace, 9, bar_join_addr, Operation::Span, 2, 0, 0);
    check_op_decoding(&dec_trace, 10, bar_basic_block_addr, Operation::Push(ONE), 1, 0, 1);
    check_op_decoding(&dec_trace, 11, bar_basic_block_addr, Operation::FmpUpdate, 0, 1, 1);
    check_op_decoding(&dec_trace, 12, bar_basic_block_addr, Operation::End, 0, 0, 0);

    // starting SYSCALL block for bar
    let syscall_addr = bar_basic_block_addr + EIGHT;
    check_op_decoding(&dec_trace, 13, bar_join_addr, Operation::SysCall, 0, 0, 0);
    // starting SPAN block within syscall
    let syscall_basic_block_addr = syscall_addr + EIGHT;
    check_op_decoding(&dec_trace, 14, syscall_addr, Operation::Span, 2, 0, 0);
    check_op_decoding(&dec_trace, 15, syscall_basic_block_addr, Operation::Push(THREE), 1, 0, 1);
    check_op_decoding(&dec_trace, 16, syscall_basic_block_addr, Operation::FmpUpdate, 0, 1, 1);
    check_op_decoding(&dec_trace, 17, syscall_basic_block_addr, Operation::End, 0, 0, 0);
    // ending SYSCALL block
    check_op_decoding(&dec_trace, 18, syscall_addr, Operation::End, 0, 0, 0);

    // ending CALL block
    check_op_decoding(&dec_trace, 19, bar_join_addr, Operation::End, 0, 0, 0);
    check_op_decoding(&dec_trace, 20, call_addr, Operation::End, 0, 0, 0);

    // ending the inner JOIN block
    check_op_decoding(&dec_trace, 21, inner_join_addr, Operation::End, 0, 0, 0);

    // starting the last SPAN block
    let last_basic_block_addr = syscall_basic_block_addr + EIGHT;
    check_op_decoding(&dec_trace, 22, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&dec_trace, 23, last_basic_block_addr, Operation::FmpAdd, 0, 0, 1);
    check_op_decoding(&dec_trace, 24, last_basic_block_addr, Operation::End, 0, 0, 0);

    // ending the program
    check_op_decoding(&dec_trace, 25, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&dec_trace, 26, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------
    // in the first row, the hasher state is set to hashes of (inner_join, last_span)
    let inner_join_hash: Word = inner_join_node.digest().into();
    let last_span_hash: Word = last_basic_block.digest().into();
    assert_eq!(inner_join_hash, get_hasher_state1(&dec_trace, 0));
    assert_eq!(last_span_hash, get_hasher_state2(&dec_trace, 0));

    // in the second row, the hasher state is set to hashes of (first_span, bar_call)
    let first_span_hash: Word = first_basic_block.digest().into();
    let bar_call_hash: Word = bar_call_node.digest().into();
    assert_eq!(first_span_hash, get_hasher_state1(&dec_trace, 1));
    assert_eq!(bar_call_hash, get_hasher_state2(&dec_trace, 1));

    // at the end of the first SPAN, the hasher state is set to the hash of the first child
    assert_eq!(first_span_hash, get_hasher_state1(&dec_trace, 6));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 6));

    // in the 7th row, we start the CALL block which has bar_join as its only child
    let bar_root_hash: Word = bar_root_node.digest().into();
    assert_eq!(bar_root_hash, get_hasher_state1(&dec_trace, 7));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 7));

    // in the 8th row, the hasher state is set to hashes of (bar_span, foo_call)
    let bar_span_hash: Word = bar_basic_block.digest().into();
    let foo_call_hash: Word = foo_call_node.digest().into();
    assert_eq!(bar_span_hash, get_hasher_state1(&dec_trace, 8));
    assert_eq!(foo_call_hash, get_hasher_state2(&dec_trace, 8));

    // at the end of the bar_span, the hasher state is set to the hash of the first child
    assert_eq!(bar_span_hash, get_hasher_state1(&dec_trace, 12));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 12));

    // in the 13th row, we start the SYSCALL block which has foo_span as its only child
    let foo_root_hash: Word = foo_root.digest().into();
    assert_eq!(foo_root_hash, get_hasher_state1(&dec_trace, 13));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 13));

    // at the end of the foo_span_hash, the hasher state is set to the hash of the first child
    assert_eq!(foo_root_hash, get_hasher_state1(&dec_trace, 17));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 17));

    // SYSCALL block ends in the 18th row; the last element of the hasher state
    // is set to ONE because we are exiting a SYSCALL block
    assert_eq!(foo_call_hash, get_hasher_state1(&dec_trace, 18));
    assert_eq!([ZERO, ZERO, ZERO, ONE], get_hasher_state2(&dec_trace, 18));

    // internal bar_join block ends in the 19th row
    assert_eq!(bar_root_hash, get_hasher_state1(&dec_trace, 19));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 19));

    // CALL block ends in the 20th row; the second to last element of the hasher state
    // is set to ONE because we are exiting a CALL block
    assert_eq!(bar_call_hash, get_hasher_state1(&dec_trace, 20));
    assert_eq!([ZERO, ZERO, ONE, ZERO], get_hasher_state2(&dec_trace, 20));

    // internal JOIN block ends in the 21st row
    assert_eq!(inner_join_hash, get_hasher_state1(&dec_trace, 21));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 21));

    // last span ends in the 24th row
    assert_eq!(last_span_hash, get_hasher_state1(&dec_trace, 24));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 24));

    // the program ends in the 25th row
    let program_hash: Word = program_root_node.digest().into();
    assert_eq!(program_hash, get_hasher_state1(&dec_trace, 25));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 25));

    // HALT opcode and program hash gets propagated to the last row
    for i in 26..trace_len {
        assert!(contains_op(&dec_trace, i, Operation::Halt));
        assert_eq!(ZERO, dec_trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, dec_trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&dec_trace, i));
    }

    // --- check the ctx column -------------------------------------------------------------------

    // for the first 7 cycles, we are in the root context
    for i in 0..8 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], ZERO);
    }

    // when CALL operation is executed, we switch to the new context; the ID of this context is 8
    // because we switch to it at the 8th cycle
    for i in 8..14 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], EIGHT);
    }

    // when SYSCALL operation is executed, we switch back to the root context (0)
    for i in 14..18 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], ZERO);
    }

    // when SYSCALL ends, we return to the context of the CALL block
    for i in 19..21 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], EIGHT);
    }

    // once the CALL block exited, we go back to the root context
    for i in 21..trace_len {
        assert_eq!(sys_trace[CTX_COL_IDX][i], ZERO);
    }

    // --- check the fmp column -------------------------------------------------------------------

    // for the first 5 cycles fmp stays at initial value
    for i in 0..5 {
        assert_eq!(sys_trace[FMP_COL_IDX][i], FMP_MIN);
    }

    // when the first FmpUpdate is executed, fmp gets gets incremented by 1
    for i in 5..8 {
        assert_eq!(sys_trace[FMP_COL_IDX][i], FMP_MIN + ONE);
    }

    // when CALL operation is executed, fmp gets reset to the initial value
    for i in 8..12 {
        assert_eq!(sys_trace[FMP_COL_IDX][i], FMP_MIN);
    }

    // when the second FmpUpdate is executed, fmp gets gets incremented by 2
    for i in 12..14 {
        assert_eq!(sys_trace[FMP_COL_IDX][i], FMP_MIN + TWO);
    }

    // when SYSCALL operation is executed, fmp gets reset to the initial value for syscalls
    for i in 14..17 {
        assert_eq!(sys_trace[FMP_COL_IDX][i], SYSCALL_FMP_MIN);
    }

    // when the third FmpUpdate is executed, fmp gets gets incremented by 3
    for i in 17..19 {
        assert_eq!(sys_trace[FMP_COL_IDX][i], SYSCALL_FMP_MIN + THREE);
    }

    // once the SYSCALL block exited, fmp gets reset back to FMP_MIN + 2
    for i in 19..21 {
        assert_eq!(sys_trace[FMP_COL_IDX][i], FMP_MIN + TWO);
    }

    // once the CALL block exited, fmp gets reset back to FMP_MIN + 1, and it remains unchanged
    // until the end of the trace
    for i in 21..trace_len {
        assert_eq!(sys_trace[FMP_COL_IDX][i], FMP_MIN + ONE);
    }

    // --- check the is_syscall column ------------------------------------------------------------

    // before the SYSCALL block, syscall flag values should be set to 0
    for i in 0..14 {
        assert_eq!(sys_trace[IN_SYSCALL_COL_IDX][i], ZERO);
    }

    // within the SYSCALL block, syscall flag values should be set to 1
    for i in 14..19 {
        assert_eq!(sys_trace[IN_SYSCALL_COL_IDX][i], ONE);
    }

    // after the SYSCALL block, syscall flag values should be set to 0 again
    for i in 19..trace_len {
        assert_eq!(sys_trace[IN_SYSCALL_COL_IDX][i], ZERO);
    }

    // --- check fn hash columns ------------------------------------------------------------------

    // before the CALL operation is executed, we are in a root context and thus fn_hash is ZEROs.
    for i in 0..8 {
        assert_eq!(get_fn_hash(&sys_trace, i), EMPTY_WORD);
    }

    // inside the CALL block (and the invoked from it SYSCALL block), fn hash is set to the hash
    // of the bar procedure
    for i in 8..21 {
        assert_eq!(get_fn_hash(&sys_trace, i), bar_root_hash);
    }

    // after the CALL block is ended, we are back in the root context
    for i in 21..trace_len {
        assert_eq!(get_fn_hash(&sys_trace, i), EMPTY_WORD);
    }
}

// DYN BLOCK TESTS
// ================================================================================================
#[test]
fn dyn_block() {
    // build a dynamic block which looks like this:
    // push.1 add

    let mut mast_forest = MastForest::new();

    let foo_root_node = MastNode::new_basic_block(vec![Operation::Push(ONE), Operation::Add]);
    let _foo_root_node_id = mast_forest.ensure_node(foo_root_node.clone());

    let mul_bb_node = MastNode::new_basic_block(vec![Operation::Mul]);
    let mul_bb_node_id = mast_forest.ensure_node(mul_bb_node.clone());

    let save_bb_node = MastNode::new_basic_block(vec![Operation::MovDn4]);
    let save_bb_node_id = mast_forest.ensure_node(save_bb_node.clone());

    let join_node = MastNode::new_join(mul_bb_node_id, save_bb_node_id, &mast_forest);
    let join_node_id = mast_forest.ensure_node(join_node.clone());

    // This dyn will point to foo.
    let dyn_node = MastNode::new_dynexec();
    let dyn_node_id = mast_forest.ensure_node(dyn_node.clone());

    let program_root_node = MastNode::new_join(join_node_id, dyn_node_id, &mast_forest);
    let program_root_node_id = mast_forest.ensure_node(program_root_node.clone());
    mast_forest.set_entrypoint(program_root_node_id);

    let program = Program::new(mast_forest).unwrap();

    let (trace, trace_len) = build_dyn_trace(
        &[
            foo_root_node.digest()[0].as_int(),
            foo_root_node.digest()[1].as_int(),
            foo_root_node.digest()[2].as_int(),
            foo_root_node.digest()[3].as_int(),
            2,
            4,
        ],
        &program,
    );

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Join, 0, 0, 0);
    // starting inner join
    let join_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Join, 0, 0, 0);
    // starting first span
    let mul_basic_block_addr = join_addr + EIGHT;
    check_op_decoding(&trace, 2, join_addr, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 3, mul_basic_block_addr, Operation::Mul, 0, 0, 1);
    check_op_decoding(&trace, 4, mul_basic_block_addr, Operation::End, 0, 0, 0);
    // starting second span
    let save_basic_block_addr = mul_basic_block_addr + EIGHT;
    check_op_decoding(&trace, 5, join_addr, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 6, save_basic_block_addr, Operation::MovDn4, 0, 0, 1);
    check_op_decoding(&trace, 7, save_basic_block_addr, Operation::End, 0, 0, 0);
    // end inner join
    check_op_decoding(&trace, 8, join_addr, Operation::End, 0, 0, 0);
    // dyn
    check_op_decoding(&trace, 9, INIT_ADDR, Operation::Dyn, 0, 0, 0);
    // starting foo span
    let dyn_addr = save_basic_block_addr + EIGHT;
    let add_basic_block_addr = dyn_addr + EIGHT;
    check_op_decoding(&trace, 10, dyn_addr, Operation::Span, 2, 0, 0);
    check_op_decoding(&trace, 11, add_basic_block_addr, Operation::Push(ONE), 1, 0, 1);
    check_op_decoding(&trace, 12, add_basic_block_addr, Operation::Add, 0, 1, 1);
    check_op_decoding(&trace, 13, add_basic_block_addr, Operation::End, 0, 0, 0);
    // end dyn
    check_op_decoding(&trace, 14, dyn_addr, Operation::End, 0, 0, 0);
    // end outer join
    check_op_decoding(&trace, 15, INIT_ADDR, Operation::End, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to hashes of both child nodes
    let join_hash: Word = join_node.digest().into();
    let dyn_hash: Word = dyn_node.digest().into();
    assert_eq!(join_hash, get_hasher_state1(&trace, 0));
    assert_eq!(dyn_hash, get_hasher_state2(&trace, 0));

    // in the second row, the hasher set is set to hashes of both child nodes of the inner JOIN
    let mul_bb_node_hash: Word = mul_bb_node.digest().into();
    let save_bb_node_hash: Word = save_bb_node.digest().into();
    assert_eq!(mul_bb_node_hash, get_hasher_state1(&trace, 1));
    assert_eq!(save_bb_node_hash, get_hasher_state2(&trace, 1));

    // at the end of the first SPAN, the hasher state is set to the hash of the first child
    assert_eq!(mul_bb_node_hash, get_hasher_state1(&trace, 4));
    assert_eq!([ZERO, ZERO, ZERO, ZERO], get_hasher_state2(&trace, 4));

    // at the end of the second SPAN, the hasher state is set to the hash of the second child
    assert_eq!(save_bb_node_hash, get_hasher_state1(&trace, 7));
    assert_eq!([ZERO, ZERO, ZERO, ZERO], get_hasher_state2(&trace, 7));

    // at the end of the inner JOIN, the hasher set is set to the hash of the JOIN
    assert_eq!(join_hash, get_hasher_state1(&trace, 8));
    assert_eq!([ZERO, ZERO, ZERO, ZERO], get_hasher_state2(&trace, 8));

    // at the start of the DYN block, the hasher state is set to the hash of its child (foo span)
    let foo_hash: Word = foo_root_node.digest().into();
    assert_eq!(foo_hash, get_hasher_state1(&trace, 9));
    assert_eq!([ZERO, ZERO, ZERO, ZERO], get_hasher_state2(&trace, 9));

    // at the end of the DYN SPAN, the hasher state is set to the hash of the foo span
    assert_eq!(foo_hash, get_hasher_state1(&trace, 13));
    assert_eq!([ZERO, ZERO, ZERO, ZERO], get_hasher_state2(&trace, 13));

    // at the end of the DYN block, the hasher state is set to the hash of the DYN node
    assert_eq!(dyn_hash, get_hasher_state1(&trace, 14));

    // at the end of the program, the hasher state is set to the hash of the entire program
    let program_hash: Word = program_root_node.digest().into();
    assert_eq!(program_hash, get_hasher_state1(&trace, 15));
    assert_eq!([ZERO, ZERO, ZERO, ZERO], get_hasher_state2(&trace, 15));

    // the HALT opcode and program hash get propagated to the last row
    for i in 16..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

// HELPER REGISTERS TESTS
// ================================================================================================
#[test]
fn set_user_op_helpers_many() {
    // --- user operation with 4 helper values ----------------------------------------------------
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block = MastNode::new_basic_block(vec![Operation::U32div]);
        let basic_block_id = mast_forest.ensure_node(basic_block);
        mast_forest.set_entrypoint(basic_block_id);

        mast_forest.try_into().unwrap()
    };
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let (dividend, divisor) = if a > b { (a, b) } else { (b, a) };
    let (trace, ..) = build_trace(&[dividend as u64, divisor as u64], &program);
    let hasher_state = get_hasher_state(&trace, 1);

    // Check the hasher state of the user operation which was executed.
    // h2 to h5 are expected to hold the values for range checks.
    let quot = dividend / divisor;
    let rem = dividend - quot * divisor;
    let check_1 = dividend - quot;
    let check_2 = divisor - rem - 1;
    let expected = build_expected_hasher_state(&[
        ZERO,
        ZERO,
        Felt::new((check_1 as u16).into()),
        Felt::new(((check_1 >> 16) as u16).into()),
        Felt::new((check_2 as u16).into()),
        Felt::new(((check_2 >> 16) as u16).into()),
    ]);

    assert_eq!(expected, hasher_state);
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_trace(stack_inputs: &[u64], program: &Program) -> (DecoderTrace, usize) {
    let stack_inputs = StackInputs::try_from_ints(stack_inputs.iter().copied()).unwrap();
    let host = DefaultHost::default();
    let mut process =
        Process::new(Kernel::default(), stack_inputs, host, ExecutionOptions::default());
    process.execute(program).unwrap();

    let (trace, _, _) = ExecutionTrace::test_finalize_trace(process);
    let trace_len = trace.num_rows() - ExecutionTrace::NUM_RAND_ROWS;

    (
        trace
            .get_column_range(DECODER_TRACE_RANGE)
            .try_into()
            .expect("failed to convert vector to array"),
        trace_len,
    )
}

fn build_dyn_trace(stack_inputs: &[u64], program: &Program) -> (DecoderTrace, usize) {
    let stack_inputs = StackInputs::try_from_ints(stack_inputs.iter().copied()).unwrap();
    let host = DefaultHost::default();
    let mut process =
        Process::new(Kernel::default(), stack_inputs, host, ExecutionOptions::default());

    process.execute(program).unwrap();

    let (trace, _, _) = ExecutionTrace::test_finalize_trace(process);
    let trace_len = trace.num_rows() - ExecutionTrace::NUM_RAND_ROWS;

    (
        trace
            .get_column_range(DECODER_TRACE_RANGE)
            .try_into()
            .expect("failed to convert vector to array"),
        trace_len,
    )
}

fn build_call_trace(program: &Program, kernel: Kernel) -> (SystemTrace, DecoderTrace, usize) {
    let host = DefaultHost::default();
    let stack_inputs = crate::StackInputs::default();
    let mut process = Process::new(kernel, stack_inputs, host, ExecutionOptions::default());

    process.execute(program).unwrap();

    let (trace, _, _) = ExecutionTrace::test_finalize_trace(process);
    let trace_len = trace.num_rows() - ExecutionTrace::NUM_RAND_ROWS;

    let sys_trace = trace
        .get_column_range(SYS_TRACE_RANGE)
        .try_into()
        .expect("failed to convert vector to array");

    let decoder_trace = trace
        .get_column_range(DECODER_TRACE_RANGE)
        .try_into()
        .expect("failed to convert vector to array");

    (sys_trace, decoder_trace, trace_len)
}

// OPCODES
// ------------------------------------------------------------------------------------------------

fn check_op_decoding(
    trace: &DecoderTrace,
    row_idx: usize,
    addr: Felt,
    op: Operation,
    group_count: u64,
    op_idx: u64,
    in_span: u64,
) {
    let opcode = read_opcode(trace, row_idx);

    assert_eq!(trace[ADDR_COL_IDX][row_idx], addr);
    assert_eq!(op.op_code(), opcode);
    assert_eq!(trace[IN_SPAN_COL_IDX][row_idx], Felt::new(in_span));
    assert_eq!(trace[GROUP_COUNT_COL_IDX][row_idx], Felt::new(group_count));
    assert_eq!(trace[OP_INDEX_COL_IDX][row_idx], Felt::new(op_idx));

    let expected_batch_flags = if op == Operation::Span || op == Operation::Respan {
        let num_groups = core::cmp::min(OP_BATCH_SIZE, group_count as usize);
        build_op_batch_flags(num_groups)
    } else {
        [ZERO, ZERO, ZERO]
    };

    for (i, flag_value) in OP_BATCH_FLAGS_RANGE.zip(expected_batch_flags) {
        assert_eq!(trace[i][row_idx], flag_value);
    }

    // make sure the op bit extra columns for degree reduction are set correctly
    let bit6 = Felt::from((opcode >> 6) & 1);
    let bit5 = Felt::from((opcode >> 5) & 1);
    let bit4 = Felt::from((opcode >> 4) & 1);
    assert_eq!(trace[OP_BITS_EXTRA_COLS_RANGE.start][row_idx], bit6 * (ONE - bit5) * bit4);
    assert_eq!(trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][row_idx], bit6 * bit5);
}

fn contains_op(trace: &DecoderTrace, row_idx: usize, op: Operation) -> bool {
    op.op_code() == read_opcode(trace, row_idx)
}

fn read_opcode(trace: &DecoderTrace, row_idx: usize) -> u8 {
    let mut result = 0;
    for (i, column) in trace.iter().skip(OP_BITS_OFFSET).take(NUM_OP_BITS).enumerate() {
        let op_bit = column[row_idx].as_int();
        assert!(op_bit <= 1, "invalid op bit");
        result += op_bit << i;
    }
    result as u8
}

fn build_op_batch_flags(num_groups: usize) -> [Felt; NUM_OP_BATCH_FLAGS] {
    match num_groups {
        1 => OP_BATCH_1_GROUPS,
        2 => OP_BATCH_2_GROUPS,
        4 => OP_BATCH_4_GROUPS,
        8 => OP_BATCH_8_GROUPS,
        _ => panic!("invalid num groups: {num_groups}"),
    }
}

// SYSTEM REGISTERS
// ------------------------------------------------------------------------------------------------

fn get_fn_hash(trace: &SystemTrace, row_idx: usize) -> Word {
    let mut result = EMPTY_WORD;
    let trace = &trace[FN_HASH_RANGE];
    for (element, column) in result.iter_mut().zip(trace) {
        *element = column[row_idx];
    }
    result
}

// HASHER STATE
// ------------------------------------------------------------------------------------------------

fn check_hasher_state(trace: &DecoderTrace, expected: Vec<Vec<Felt>>) {
    for (i, expected) in expected.iter().enumerate() {
        let expected = build_expected_hasher_state(expected);
        assert_eq!(expected, get_hasher_state(trace, i));
    }
}

fn get_hasher_state(trace: &DecoderTrace, row_idx: usize) -> [Felt; NUM_HASHER_COLUMNS] {
    let mut result = [ZERO; NUM_HASHER_COLUMNS];
    for (result, column) in result.iter_mut().zip(trace[HASHER_STATE_RANGE].iter()) {
        *result = column[row_idx];
    }
    result
}

fn get_hasher_state1(trace: &DecoderTrace, row_idx: usize) -> Word {
    let mut result = EMPTY_WORD;
    for (result, column) in result.iter_mut().zip(trace[HASHER_STATE_RANGE].iter()) {
        *result = column[row_idx];
    }
    result
}

fn get_hasher_state2(trace: &DecoderTrace, row_idx: usize) -> Word {
    let mut result = EMPTY_WORD;
    for (result, column) in result.iter_mut().zip(trace[HASHER_STATE_RANGE].iter().skip(4)) {
        *result = column[row_idx];
    }
    result
}

fn build_expected_hasher_state(values: &[Felt]) -> [Felt; NUM_HASHER_COLUMNS] {
    let mut result = [ZERO; NUM_HASHER_COLUMNS];
    for (i, value) in values.iter().enumerate() {
        result[i] = *value;
    }
    result
}
