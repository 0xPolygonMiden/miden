use super::{super::trace::AuxColumnBuilder, Felt, FieldElement, StarkField, Vec};

use miden_air::trace::{
    chiplets::{
        bitwise::OP_CYCLE_LEN as BITWISE_OP_CYCLE_LEN,
        hasher::{
            CAPACITY_LEN, DIGEST_RANGE, HASH_CYCLE_LEN, LINEAR_HASH_LABEL, MP_VERIFY_LABEL,
            MR_UPDATE_NEW_LABEL, MR_UPDATE_OLD_LABEL, NUM_ROUNDS, RETURN_HASH_LABEL,
            RETURN_STATE_LABEL, STATE_WIDTH,
        },
        kernel_rom::KERNEL_PROC_LABEL,
        memory::{MEMORY_READ_LABEL, MEMORY_WRITE_LABEL},
    },
    main_trace::MainTrace,
};

use vm_core::{Operation, ONE, ZERO};

// CONSTANTS
// ================================================================================================

const JOIN: u8 = Operation::Join.op_code();
const SPLIT: u8 = Operation::Split.op_code();
const LOOP: u8 = Operation::Loop.op_code();
const DYN: u8 = Operation::Dyn.op_code();
const CALL: u8 = Operation::Call.op_code();
const SYSCALL: u8 = Operation::SysCall.op_code();
const SPAN: u8 = Operation::Span.op_code();
const RESPAN: u8 = Operation::Respan.op_code();
const END: u8 = Operation::End.op_code();
const AND: u8 = Operation::U32and.op_code();
const XOR: u8 = Operation::U32xor.op_code();
const MLOADW: u8 = Operation::MLoadW.op_code();
const MSTOREW: u8 = Operation::MStoreW.op_code();
const MLOAD: u8 = Operation::MLoad.op_code();
const MSTORE: u8 = Operation::MStore.op_code();
const MSTREAM: u8 = Operation::MStream.op_code();
const RCOMBBASE: u8 = Operation::RCombBase.op_code();
const HPERM: u8 = Operation::HPerm.op_code();
const MPVERIFY: u8 = Operation::MpVerify.op_code();
const MRUPDATE: u8 = Operation::MrUpdate.op_code();
const NUM_HEADER_ALPHAS: usize = 4;

// CHIPLETS AUXILIARY TRACE BUILDER
// ================================================================================================

/// Constructs the execution trace for chiplets-related auxiliary columns (used in multiset checks).
#[derive(Default)]
pub struct AuxTraceBuilder {}

impl AuxTraceBuilder {
    // COLUMN TRACE CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Builds and returns the Chiplets's auxiliary trace columns. Currently this consists of
    /// a single bus column `b_chip` describing chiplet lookups requested by the stack and
    /// provided by chiplets in the Chiplets module.
    pub fn build_aux_columns<E: FieldElement<BaseField = Felt>>(
        &self,
        main_trace: &MainTrace,
        rand_elements: &[E],
    ) -> Vec<Vec<E>> {
        let v_table_col_builder = ChipletsVTableColBuilder::default();
        let bus_col_builder = BusColumnBuilder::default();
        let t_chip = v_table_col_builder.build_aux_column(main_trace, rand_elements);
        let b_chip = bus_col_builder.build_aux_column(main_trace, rand_elements);
        vec![t_chip, b_chip]
    }
}

// BUS TRACE BUILDER
// ================================================================================================

/// Describes how to construct the execution trace of the chiplets bus auxiliary trace column.
#[derive(Default)]
pub struct BusColumnBuilder {}

impl<E: FieldElement<BaseField = Felt>> AuxColumnBuilder<E> for BusColumnBuilder {
    /// Constructs the requests made by the VM-components to the chiplets at row i.
    fn get_requests_at(&self, main_trace: &MainTrace, alphas: &[E], i: usize) -> E
    where
        E: FieldElement<BaseField = Felt>,
    {
        let op_code_felt = main_trace.get_op_code(i);
        let op_code = op_code_felt.as_int() as u8;

        match op_code {
            JOIN | SPLIT | LOOP | DYN | CALL => {
                build_control_block_request(main_trace, op_code_felt, alphas, i)
            }
            SYSCALL => build_syscall_block_request(main_trace, op_code_felt, alphas, i),
            SPAN => build_span_block_request(main_trace, alphas, i),
            RESPAN => build_respan_block_request(main_trace, alphas, i),
            END => build_end_block_request(main_trace, alphas, i),
            AND => build_bitwise_request(main_trace, ZERO, alphas, i),
            XOR => build_bitwise_request(main_trace, ONE, alphas, i),
            MLOADW => build_mem_request(main_trace, MEMORY_READ_LABEL, true, alphas, i),
            MSTOREW => build_mem_request(main_trace, MEMORY_WRITE_LABEL, true, alphas, i),
            MLOAD => build_mem_request(main_trace, MEMORY_READ_LABEL, false, alphas, i),
            MSTORE => build_mem_request(main_trace, MEMORY_WRITE_LABEL, false, alphas, i),
            MSTREAM => build_mstream_request(main_trace, alphas, i),
            RCOMBBASE => build_rcomb_base_request(main_trace, alphas, i),
            HPERM => build_hperm_request(main_trace, alphas, i),
            MPVERIFY => build_mpverify_request(main_trace, alphas, i),
            MRUPDATE => build_mrupdate_request(main_trace, alphas, i),
            _ => E::ONE,
        }
    }

    /// Constructs the responses from the chiplets to the other VM-components at row i.
    fn get_responses_at(&self, main_trace: &MainTrace, alphas: &[E], i: usize) -> E
    where
        E: FieldElement<BaseField = Felt>,
    {
        let selector0 = main_trace.chiplet_selector_0(i);
        let selector1 = main_trace.chiplet_selector_1(i);
        let selector2 = main_trace.chiplet_selector_2(i);
        let selector3 = main_trace.chiplet_selector_3(i);
        let selector4 = main_trace.chiplet_selector_4(i);

        if selector0 == ZERO {
            build_hasher_chiplet_responses(main_trace, i, alphas, selector1, selector2, selector3)
        } else if selector1 == ZERO {
            debug_assert_eq!(selector0, ONE);
            build_bitwise_chiplet_responses(main_trace, i, selector2, alphas)
        } else if selector2 == ZERO {
            debug_assert_eq!(selector0, ONE);
            debug_assert_eq!(selector1, ONE);
            build_memory_chiplet_responses(main_trace, i, selector3, alphas)
        } else if selector3 == ZERO && selector4 == ONE {
            debug_assert_eq!(selector0, ONE);
            debug_assert_eq!(selector1, ONE);
            debug_assert_eq!(selector2, ONE);
            build_kernel_chiplet_responses(main_trace, i, alphas)
        } else {
            debug_assert_eq!(selector0, ONE);
            debug_assert_eq!(selector1, ONE);
            debug_assert_eq!(selector2, ONE);
            debug_assert_eq!(selector3, ONE);
            E::ONE
        }
    }
}

// VIRTUAL TABLE TRACE BUILDER
// ================================================================================================

/// Describes how to construct the execution trace of the chiplets virtual table auxiliary trace
/// column.
#[derive(Default)]
pub struct ChipletsVTableColBuilder {}

impl<E: FieldElement<BaseField = Felt>> AuxColumnBuilder<E> for ChipletsVTableColBuilder {
    fn get_requests_at(&self, main_trace: &MainTrace, alphas: &[E], i: usize) -> E {
        chiplets_vtable_remove_sibling(main_trace, alphas, i)
    }

    fn get_responses_at(&self, main_trace: &MainTrace, alphas: &[E], i: usize) -> E {
        chiplets_vtable_add_sibling(main_trace, alphas, i)
            * chiplets_kernel_table_include(main_trace, alphas, i)
    }
}

// CHIPLETS VIRTUAL TABLE REQUESTS
// ================================================================================================

/// Constructs the inclusions to the table when the hasher absorbs a new sibling node while
/// computing the old Merkle root.
fn chiplets_vtable_add_sibling<E>(main_trace: &MainTrace, alphas: &[E], i: usize) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    let f_mv: bool = main_trace.f_mv(i);
    let f_mva: bool = if i == 0 { false } else { main_trace.f_mva(i - 1) };

    if f_mv || f_mva {
        let index = if f_mva {
            main_trace.chiplet_node_index(i - 1)
        } else {
            main_trace.chiplet_node_index(i)
        };
        let lsb = index.as_int() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(i)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[12].mul_base(sibling[0])
                + alphas[13].mul_base(sibling[1])
                + alphas[14].mul_base(sibling[2])
                + alphas[15].mul_base(sibling[3])
        } else {
            let sibling = &main_trace.chiplet_hasher_state(i)[DIGEST_RANGE];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[8].mul_base(sibling[0])
                + alphas[9].mul_base(sibling[1])
                + alphas[10].mul_base(sibling[2])
                + alphas[11].mul_base(sibling[3])
        }
    } else {
        E::ONE
    }
}

/// Constructs the removals from the table when the hasher absorbs a new sibling node while
/// computing the new Merkle root.
fn chiplets_vtable_remove_sibling<E>(main_trace: &MainTrace, alphas: &[E], i: usize) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    let f_mu: bool = main_trace.f_mu(i);
    let f_mua: bool = if i == 0 { false } else { main_trace.f_mua(i - 1) };

    if f_mu || f_mua {
        let index = if f_mua {
            main_trace.chiplet_node_index(i - 1)
        } else {
            main_trace.chiplet_node_index(i)
        };
        let lsb = index.as_int() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(i)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[12].mul_base(sibling[0])
                + alphas[13].mul_base(sibling[1])
                + alphas[14].mul_base(sibling[2])
                + alphas[15].mul_base(sibling[3])
        } else {
            let sibling = &main_trace.chiplet_hasher_state(i)[DIGEST_RANGE];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[8].mul_base(sibling[0])
                + alphas[9].mul_base(sibling[1])
                + alphas[10].mul_base(sibling[2])
                + alphas[11].mul_base(sibling[3])
        }
    } else {
        E::ONE
    }
}

/// Constructs the inclusions to the kernel table.
fn chiplets_kernel_table_include<E>(main_trace: &MainTrace, alphas: &[E], i: usize) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    if main_trace.is_kernel_row(i) && main_trace.is_addr_change(i) {
        alphas[0]
            + alphas[1].mul_base(main_trace.addr(i))
            + alphas[2].mul_base(main_trace.chiplet_kernel_root_0(i))
            + alphas[3].mul_base(main_trace.chiplet_kernel_root_1(i))
            + alphas[4].mul_base(main_trace.chiplet_kernel_root_2(i))
            + alphas[5].mul_base(main_trace.chiplet_kernel_root_3(i))
    } else {
        E::ONE
    }
}

// CHIPLETS REQUESTS
// ================================================================================================

/// Builds requests made to the hasher chiplet at the start of a control block.
fn build_control_block_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    op_code_felt: Felt,
    alphas: &[E],
    i: usize,
) -> E {
    let op_label = LINEAR_HASH_LABEL;
    let addr_nxt = main_trace.addr(i + 1);
    let first_cycle_row = addr_to_row_index(addr_nxt) % HASH_CYCLE_LEN == 0;
    let transition_label = if first_cycle_row { op_label + 16 } else { op_label + 32 };

    let header =
        alphas[0] + alphas[1].mul_base(Felt::from(transition_label)) + alphas[2].mul_base(addr_nxt);

    let state = main_trace.decoder_hasher_state(i);

    header + build_value(&alphas[8..16], &state) + alphas[5].mul_base(op_code_felt)
}

/// Builds requests made to kernel ROM chiplet when initializing a syscall block.
fn build_syscall_block_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    op_code_felt: Felt,
    alphas: &[E],
    i: usize,
) -> E {
    let factor1 = build_control_block_request(main_trace, op_code_felt, alphas, i);

    let op_label = KERNEL_PROC_LABEL;
    let state = main_trace.decoder_hasher_state(i);
    let factor2 = alphas[0]
        + alphas[1].mul_base(op_label)
        + alphas[2].mul_base(state[0])
        + alphas[3].mul_base(state[1])
        + alphas[4].mul_base(state[2])
        + alphas[5].mul_base(state[3]);

    factor1 * factor2
}

/// Builds requests made to the hasher chiplet at the start of a span block.
fn build_span_block_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    i: usize,
) -> E {
    let op_label = LINEAR_HASH_LABEL;
    let addr_nxt = main_trace.addr(i + 1);
    let first_cycle_row = addr_to_row_index(addr_nxt) % HASH_CYCLE_LEN == 0;
    let transition_label = if first_cycle_row { op_label + 16 } else { op_label + 32 };

    let header =
        alphas[0] + alphas[1].mul_base(Felt::from(transition_label)) + alphas[2].mul_base(addr_nxt);

    let state = main_trace.decoder_hasher_state(i);

    header + build_value(&alphas[8..16], &state)
}

/// Builds requests made to the hasher chiplet at the start of a respan block.
fn build_respan_block_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    i: usize,
) -> E {
    let op_label = LINEAR_HASH_LABEL;
    let addr_nxt = main_trace.addr(i + 1);

    let first_cycle_row = addr_to_row_index(addr_nxt - ONE) % HASH_CYCLE_LEN == 0;
    let transition_label = if first_cycle_row { op_label + 16 } else { op_label + 32 };

    let header = alphas[0]
        + alphas[1].mul_base(Felt::from(transition_label))
        + alphas[2].mul_base(addr_nxt - ONE)
        + alphas[3].mul_base(ZERO);

    let state = &main_trace.chiplet_hasher_state(i - 2)[CAPACITY_LEN..];
    let state_nxt = &main_trace.chiplet_hasher_state(i - 1)[CAPACITY_LEN..];

    header + build_value(&alphas[8..16], state_nxt) - build_value(&alphas[8..16], state)
}

/// Builds requests made to the hasher chiplet at the end of a block.
fn build_end_block_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    i: usize,
) -> E {
    let op_label = RETURN_HASH_LABEL;
    let addr = main_trace.addr(i) + Felt::from(NUM_ROUNDS as u8);

    let first_cycle_row = addr_to_row_index(addr) % HASH_CYCLE_LEN == 0;
    let transition_label = if first_cycle_row { op_label + 16 } else { op_label + 32 };

    let header =
        alphas[0] + alphas[1].mul_base(Felt::from(transition_label)) + alphas[2].mul_base(addr);

    let state = main_trace.decoder_hasher_state(i);
    let digest = &state[..4];

    header + build_value(&alphas[8..12], digest)
}

/// Builds requests made to the bitwise chiplet. This can be either a request for the computation
/// of a `XOR` or an `AND` operation.
fn build_bitwise_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    is_xor: Felt,
    alphas: &[E],
    i: usize,
) -> E {
    let op_label = get_op_label(ONE, ZERO, is_xor, ZERO);
    let a = main_trace.stack_element(1, i);
    let b = main_trace.stack_element(0, i);
    let z = main_trace.stack_element(0, i + 1);

    alphas[0]
        + alphas[1].mul_base(op_label)
        + alphas[2].mul_base(a)
        + alphas[3].mul_base(b)
        + alphas[4].mul_base(z)
}

/// Builds `MLOAD*` and `MSTORE*` requests made to the memory chiplet.
fn build_mem_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    op_label: u8,
    word: bool,
    alphas: &[E],
    i: usize,
) -> E {
    let ctx = main_trace.ctx(i);
    let clk = main_trace.clk(i);

    let (v0, v1, v2, v3) = if word {
        (
            main_trace.stack_element(0, i + 1),
            main_trace.stack_element(1, i + 1),
            main_trace.stack_element(2, i + 1),
            main_trace.stack_element(3, i + 1),
        )
    } else {
        (
            main_trace.helper_0(i),
            main_trace.helper_1(i),
            main_trace.helper_2(i),
            main_trace.stack_element(0, i + 1),
        )
    };

    let s0_cur = main_trace.stack_element(0, i);

    alphas[0]
        + alphas[1].mul_base(Felt::from(op_label))
        + alphas[2].mul_base(ctx)
        + alphas[3].mul_base(s0_cur)
        + alphas[4].mul_base(clk)
        + alphas[5].mul_base(v3)
        + alphas[6].mul_base(v2)
        + alphas[7].mul_base(v1)
        + alphas[8].mul_base(v0)
}

/// Builds `MSTREAM` requests made to the memory chiplet.
fn build_mstream_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    i: usize,
) -> E {
    let ctx = main_trace.ctx(i);
    let clk = main_trace.clk(i);

    let s0_nxt = main_trace.stack_element(0, i + 1);
    let s1_nxt = main_trace.stack_element(1, i + 1);
    let s2_nxt = main_trace.stack_element(2, i + 1);
    let s3_nxt = main_trace.stack_element(3, i + 1);
    let s4_nxt = main_trace.stack_element(4, i + 1);
    let s5_nxt = main_trace.stack_element(5, i + 1);
    let s6_nxt = main_trace.stack_element(6, i + 1);
    let s7_nxt = main_trace.stack_element(7, i + 1);

    let s12_cur = main_trace.stack_element(12, i);

    let op_label = MEMORY_READ_LABEL;

    let factor1 = alphas[0]
        + alphas[1].mul_base(Felt::from(op_label))
        + alphas[2].mul_base(ctx)
        + alphas[3].mul_base(s12_cur)
        + alphas[4].mul_base(clk)
        + alphas[5].mul_base(s7_nxt)
        + alphas[6].mul_base(s6_nxt)
        + alphas[7].mul_base(s5_nxt)
        + alphas[8].mul_base(s4_nxt);

    let factor2 = alphas[0]
        + alphas[1].mul_base(Felt::from(op_label))
        + alphas[2].mul_base(ctx)
        + alphas[3].mul_base(s12_cur + ONE)
        + alphas[4].mul_base(clk)
        + alphas[5].mul_base(s3_nxt)
        + alphas[6].mul_base(s2_nxt)
        + alphas[7].mul_base(s1_nxt)
        + alphas[8].mul_base(s0_nxt);
    factor1 * factor2
}

/// Builds `RCOMBBASE` requests made to the memory chiplet.
fn build_rcomb_base_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    i: usize,
) -> E {
    let ctx = main_trace.ctx(i);
    let clk = main_trace.clk(i);

    let tz0 = main_trace.helper_i(0, i);
    let tz1 = main_trace.helper_i(1, i);
    let tzg0 = main_trace.helper_i(2, i);
    let tzg1 = main_trace.helper_i(3, i);
    let a0 = main_trace.helper_i(4, i);
    let a1 = main_trace.helper_i(5, i);

    let z_ptr = main_trace.stack_element(13, i);
    let a_ptr = main_trace.stack_element(14, i);

    let op_label = MEMORY_READ_LABEL;

    let factor1 = alphas[0]
        + alphas[1].mul_base(Felt::from(op_label))
        + alphas[2].mul_base(ctx)
        + alphas[3].mul_base(z_ptr)
        + alphas[4].mul_base(clk)
        + alphas[5].mul_base(tz0)
        + alphas[6].mul_base(tz1)
        + alphas[7].mul_base(tzg0)
        + alphas[8].mul_base(tzg1);

    let factor2 = alphas[0]
        + alphas[1].mul_base(Felt::from(op_label))
        + alphas[2].mul_base(ctx)
        + alphas[3].mul_base(a_ptr)
        + alphas[4].mul_base(clk)
        + alphas[5].mul_base(a0)
        + alphas[6].mul_base(a1)
        + alphas[7].mul_base(ZERO)
        + alphas[8].mul_base(ZERO);
    factor1 * factor2
}

/// Builds `HPERM` requests made to the hash chiplet.
fn build_hperm_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    i: usize,
) -> E {
    let helper_0 = main_trace.helper_0(i);

    let s0_s12_cur = [
        main_trace.stack_element(0, i),
        main_trace.stack_element(1, i),
        main_trace.stack_element(2, i),
        main_trace.stack_element(3, i),
        main_trace.stack_element(4, i),
        main_trace.stack_element(5, i),
        main_trace.stack_element(6, i),
        main_trace.stack_element(7, i),
        main_trace.stack_element(8, i),
        main_trace.stack_element(9, i),
        main_trace.stack_element(10, i),
        main_trace.stack_element(11, i),
    ];

    let s0_s12_nxt = [
        main_trace.stack_element(0, i + 1),
        main_trace.stack_element(1, i + 1),
        main_trace.stack_element(2, i + 1),
        main_trace.stack_element(3, i + 1),
        main_trace.stack_element(4, i + 1),
        main_trace.stack_element(5, i + 1),
        main_trace.stack_element(6, i + 1),
        main_trace.stack_element(7, i + 1),
        main_trace.stack_element(8, i + 1),
        main_trace.stack_element(9, i + 1),
        main_trace.stack_element(10, i + 1),
        main_trace.stack_element(11, i + 1),
    ];

    let op_label = LINEAR_HASH_LABEL;
    let op_label = if addr_to_hash_cycle(helper_0) == 0 {
        op_label + 16
    } else {
        op_label + 32
    };

    let sum_input = alphas[4..16]
        .iter()
        .rev()
        .enumerate()
        .fold(E::ZERO, |acc, (i, x)| acc + x.mul_base(s0_s12_cur[i]));
    let v_input = alphas[0]
        + alphas[1].mul_base(Felt::from(op_label))
        + alphas[2].mul_base(helper_0)
        + sum_input;

    let op_label = RETURN_STATE_LABEL;
    let op_label = if addr_to_hash_cycle(helper_0 + Felt::new(7)) == 0 {
        op_label + 16
    } else {
        op_label + 32
    };

    let sum_output = alphas[4..16]
        .iter()
        .rev()
        .enumerate()
        .fold(E::ZERO, |acc, (i, x)| acc + x.mul_base(s0_s12_nxt[i]));
    let v_output = alphas[0]
        + alphas[1].mul_base(Felt::from(op_label))
        + alphas[2].mul_base(helper_0 + Felt::new(7))
        + sum_output;

    v_input * v_output
}

/// Builds `MPVERIFY` requests made to the hash chiplet.
fn build_mpverify_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    i: usize,
) -> E {
    let helper_0 = main_trace.helper_0(i);

    let s0_s3 = [
        main_trace.stack_element(0, i),
        main_trace.stack_element(1, i),
        main_trace.stack_element(2, i),
        main_trace.stack_element(3, i),
    ];
    let s4 = main_trace.stack_element(4, i);
    let s5 = main_trace.stack_element(5, i);
    let s6_s9 = [
        main_trace.stack_element(6, i),
        main_trace.stack_element(7, i),
        main_trace.stack_element(8, i),
        main_trace.stack_element(9, i),
    ];

    let op_label = MP_VERIFY_LABEL;
    let op_label = if addr_to_hash_cycle(helper_0) == 0 {
        op_label + 16
    } else {
        op_label + 32
    };

    let sum_input = alphas[8..12]
        .iter()
        .rev()
        .enumerate()
        .fold(E::ZERO, |acc, (i, x)| acc + x.mul_base(s0_s3[i]));

    let v_input = alphas[0]
        + alphas[1].mul_base(Felt::from(op_label))
        + alphas[2].mul_base(helper_0)
        + alphas[3].mul_base(s5)
        + sum_input;

    let op_label = RETURN_HASH_LABEL;
    let op_label = if (helper_0).as_int() % 8 == 0 {
        op_label + 16
    } else {
        op_label + 32
    };

    let sum_output = alphas[8..12]
        .iter()
        .rev()
        .enumerate()
        .fold(E::ZERO, |acc, (i, x)| acc + x.mul_base(s6_s9[i]));
    let v_output = alphas[0]
        + alphas[1].mul_base(Felt::from(op_label))
        + alphas[2].mul_base(helper_0 + s4.mul_small(8) - ONE)
        + sum_output;

    v_input * v_output
}

/// Builds `MRUPDATE` requests made to the hash chiplet.
fn build_mrupdate_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    i: usize,
) -> E {
    let helper_0 = main_trace.helper_0(i);

    let s0_s3 = [
        main_trace.stack_element(0, i),
        main_trace.stack_element(1, i),
        main_trace.stack_element(2, i),
        main_trace.stack_element(3, i),
    ];
    let s0_s3_nxt = [
        main_trace.stack_element(0, i + 1),
        main_trace.stack_element(1, i + 1),
        main_trace.stack_element(2, i + 1),
        main_trace.stack_element(3, i + 1),
    ];
    let s4 = main_trace.stack_element(4, i);
    let s5 = main_trace.stack_element(5, i);
    let s6_s9 = [
        main_trace.stack_element(6, i),
        main_trace.stack_element(7, i),
        main_trace.stack_element(8, i),
        main_trace.stack_element(9, i),
    ];
    let s10_s13 = [
        main_trace.stack_element(10, i),
        main_trace.stack_element(11, i),
        main_trace.stack_element(12, i),
        main_trace.stack_element(13, i),
    ];

    let op_label = MR_UPDATE_OLD_LABEL;
    let op_label = if addr_to_hash_cycle(helper_0) == 0 {
        op_label + 16
    } else {
        op_label + 32
    };

    let sum_input = alphas[8..12]
        .iter()
        .rev()
        .enumerate()
        .fold(E::ZERO, |acc, (i, x)| acc + x.mul_base(s0_s3[i]));
    let v_input_old = alphas[0]
        + alphas[1].mul_base(Felt::from(op_label))
        + alphas[2].mul_base(helper_0)
        + alphas[3].mul_base(s5)
        + sum_input;

    let op_label = RETURN_HASH_LABEL;
    let op_label = if addr_to_hash_cycle(helper_0 + s4.mul_small(8) - ONE) == 0 {
        op_label + 16
    } else {
        op_label + 32
    };

    let sum_output = alphas[8..12]
        .iter()
        .rev()
        .enumerate()
        .fold(E::ZERO, |acc, (i, x)| acc + x.mul_base(s6_s9[i]));
    let v_output_old = alphas[0]
        + alphas[1].mul_base(Felt::from(op_label))
        + alphas[2].mul_base(helper_0 + s4.mul_small(8) - ONE)
        + sum_output;

    let op_label = MR_UPDATE_NEW_LABEL;
    let op_label = if addr_to_hash_cycle(helper_0 + s4.mul_small(8)) == 0 {
        op_label + 16
    } else {
        op_label + 32
    };
    let sum_input = alphas[8..12]
        .iter()
        .rev()
        .enumerate()
        .fold(E::ZERO, |acc, (i, x)| acc + x.mul_base(s10_s13[i]));
    let v_input_new = alphas[0]
        + alphas[1].mul_base(Felt::from(op_label))
        + alphas[2].mul_base(helper_0 + s4.mul_small(8))
        + alphas[3].mul_base(s5)
        + sum_input;

    let op_label = RETURN_HASH_LABEL;
    let op_label = if addr_to_hash_cycle(helper_0 + s4.mul_small(16) - ONE) == 0 {
        op_label + 16
    } else {
        op_label + 32
    };

    let sum_output = alphas[8..12]
        .iter()
        .rev()
        .enumerate()
        .fold(E::ZERO, |acc, (i, x)| acc + x.mul_base(s0_s3_nxt[i]));
    let v_output_new = alphas[0]
        + alphas[1].mul_base(Felt::from(op_label))
        + alphas[2].mul_base(helper_0 + s4.mul_small(16) - ONE)
        + sum_output;

    v_input_new * v_input_old * v_output_new * v_output_old
}

// CHIPLETS RESPONSES
// ================================================================================================

/// Builds the response from the hasher chiplet at row `i`.
fn build_hasher_chiplet_responses<E>(
    main_trace: &MainTrace,
    i: usize,
    alphas: &[E],
    selector1: Felt,
    selector2: Felt,
    selector3: Felt,
) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    let mut multiplicand = E::ONE;
    let selector0 = main_trace.chiplet_selector_0(i);
    let op_label = get_op_label(selector0, selector1, selector2, selector3);

    // f_bp, f_mp, f_mv or f_mu == 1
    if i % HASH_CYCLE_LEN == 0 {
        let state = main_trace.chiplet_hasher_state(i);
        let alphas_state = &alphas[NUM_HEADER_ALPHAS..(NUM_HEADER_ALPHAS + STATE_WIDTH)];
        let node_index = main_trace.chiplet_node_index(i);
        let transition_label = op_label + Felt::from(16_u8);

        // f_bp == 1
        // v_all = v_h + v_a + v_b + v_c
        if selector1 == ONE && selector2 == ZERO && selector3 == ZERO {
            let header = alphas[0]
                + alphas[1].mul_base(transition_label)
                + alphas[2].mul_base(Felt::from((i + 1) as u64))
                + alphas[3].mul_base(node_index);

            multiplicand = header + build_value(alphas_state, &state);
        }

        // f_mp or f_mv or f_mu == 1
        // v_leaf = v_h + (1 - b) * v_b + b * v_d
        if selector1 == ONE && !(selector2 == ZERO && selector3 == ZERO) {
            let header = alphas[0]
                + alphas[1].mul_base(transition_label)
                + alphas[2].mul_base(Felt::from((i + 1) as u64))
                + alphas[3].mul_base(node_index);

            let bit = node_index.as_int() & 1;
            let left_word = build_value(&alphas_state[DIGEST_RANGE], &state[DIGEST_RANGE]);
            let right_word = build_value(&alphas_state[DIGEST_RANGE], &state[DIGEST_RANGE.end..]);

            multiplicand = header + E::from(1 - bit).mul(left_word) + E::from(bit).mul(right_word);
        }
    }

    // f_hout, f_sout, f_abp == 1
    if i % HASH_CYCLE_LEN == HASH_CYCLE_LEN - 1 {
        let state = main_trace.chiplet_hasher_state(i);
        let alphas_state = &alphas[NUM_HEADER_ALPHAS..(NUM_HEADER_ALPHAS + STATE_WIDTH)];
        let node_index = main_trace.chiplet_node_index(i);
        let transition_label = op_label + Felt::from(32_u8);

        // f_hout == 1
        // v_res = v_h + v_b;
        if selector1 == ZERO && selector2 == ZERO && selector3 == ZERO {
            let header = alphas[0]
                + alphas[1].mul_base(transition_label)
                + alphas[2].mul_base(Felt::from((i + 1) as u64))
                + alphas[3].mul_base(node_index);

            multiplicand = header + build_value(&alphas_state[DIGEST_RANGE], &state[DIGEST_RANGE]);
        }

        // f_sout == 1
        // v_all = v_h + v_a + v_b + v_c
        if selector1 == ZERO && selector2 == ZERO && selector3 == ONE {
            let header = alphas[0]
                + alphas[1].mul_base(transition_label)
                + alphas[2].mul_base(Felt::from((i + 1) as u64))
                + alphas[3].mul_base(node_index);

            multiplicand = header + build_value(alphas_state, &state);
        }

        // f_abp == 1
        // v_abp = v_h + v_b' + v_c' - v_b - v_c
        if selector1 == ONE && selector2 == ZERO && selector3 == ZERO {
            let header = alphas[0]
                + alphas[1].mul_base(transition_label)
                + alphas[2].mul_base(Felt::from((i + 1) as u64))
                + alphas[3].mul_base(node_index);

            let state_nxt = main_trace.chiplet_hasher_state(i + 1);

            // build the value from the difference of the hasher state's just before and right
            // after the absorption of new elements.
            let next_state_value =
                build_value(&alphas_state[CAPACITY_LEN..], &state_nxt[CAPACITY_LEN..]);
            let state_value = build_value(&alphas_state[CAPACITY_LEN..], &state[CAPACITY_LEN..]);

            multiplicand = header + next_state_value - state_value;
        }
    }
    multiplicand
}

/// Builds the response from the bitwise chiplet at row `i`.
fn build_bitwise_chiplet_responses<E>(
    main_trace: &MainTrace,
    i: usize,
    is_xor: Felt,
    alphas: &[E],
) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    if i % BITWISE_OP_CYCLE_LEN == BITWISE_OP_CYCLE_LEN - 1 {
        let op_label = get_op_label(ONE, ZERO, is_xor, ZERO);

        let a = main_trace.chiplet_bitwise_a(i);
        let b = main_trace.chiplet_bitwise_b(i);
        let z = main_trace.chiplet_bitwise_z(i);

        alphas[0]
            + alphas[1].mul_base(op_label)
            + alphas[2].mul_base(a)
            + alphas[3].mul_base(b)
            + alphas[4].mul_base(z)
    } else {
        E::ONE
    }
}

/// Builds the response from the memory chiplet at row `i`.
fn build_memory_chiplet_responses<E>(
    main_trace: &MainTrace,
    i: usize,
    is_read: Felt,
    alphas: &[E],
) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    let op_label = get_op_label(ONE, ONE, ZERO, is_read);

    let ctx = main_trace.chiplet_memory_ctx(i);
    let clk = main_trace.chiplet_memory_clk(i);
    let addr = main_trace.chiplet_memory_addr(i);
    let value0 = main_trace.chiplet_memory_value_0(i);
    let value1 = main_trace.chiplet_memory_value_1(i);
    let value2 = main_trace.chiplet_memory_value_2(i);
    let value3 = main_trace.chiplet_memory_value_3(i);

    alphas[0]
        + alphas[1].mul_base(op_label)
        + alphas[2].mul_base(ctx)
        + alphas[3].mul_base(addr)
        + alphas[4].mul_base(clk)
        + alphas[5].mul_base(value0)
        + alphas[6].mul_base(value1)
        + alphas[7].mul_base(value2)
        + alphas[8].mul_base(value3)
}

/// Builds the response from the kernel chiplet at row `i`.
fn build_kernel_chiplet_responses<E>(main_trace: &MainTrace, i: usize, alphas: &[E]) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    let op_label = KERNEL_PROC_LABEL;

    let root0 = main_trace.chiplet_kernel_root_0(i);
    let root1 = main_trace.chiplet_kernel_root_1(i);
    let root2 = main_trace.chiplet_kernel_root_2(i);
    let root3 = main_trace.chiplet_kernel_root_3(i);

    alphas[0]
        + alphas[1].mul_base(op_label)
        + alphas[2].mul_base(root0)
        + alphas[3].mul_base(root1)
        + alphas[4].mul_base(root2)
        + alphas[5].mul_base(root3)
}

/// Reduces a slice of elements to a single field element in the field specified by E using a slice
/// of alphas of matching length. This can be used to build the value for a single word or for an
/// entire [HasherState].
fn build_value<E: FieldElement<BaseField = Felt>>(alphas: &[E], elements: &[Felt]) -> E {
    assert_eq!(alphas.len(), elements.len());
    let mut value = E::ZERO;
    for (&alpha, &element) in alphas.iter().zip(elements.iter()) {
        value += alpha.mul_base(element);
    }
    value
}

/// Returns the operation unique label.
fn get_op_label(s0: Felt, s1: Felt, s2: Felt, s3: Felt) -> Felt {
    s3.mul_small(1 << 3) + s2.mul_small(1 << 2) + s1.mul_small(2) + s0 + ONE
}

/// Returns the hash cycle corresponding to the provided Hasher address.
fn addr_to_hash_cycle(addr: Felt) -> usize {
    let row = (addr.as_int() - 1) as usize;
    let cycle_row = row % HASH_CYCLE_LEN;
    debug_assert!(cycle_row == 0 || cycle_row == HASH_CYCLE_LEN - 1, "invalid address for hasher");

    cycle_row
}

/// Convenience method to convert from addresses to rows.
fn addr_to_row_index(addr: Felt) -> usize {
    (addr.as_int() - 1) as usize
}
