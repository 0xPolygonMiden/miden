use crate::trace::AuxColumnBuilder;

use super::{ColMatrix, Felt, FieldElement, OverflowTableRow, Vec};
use miden_air::trace::main_trace::MainTrace;

// AUXILIARY TRACE BUILDER
// ================================================================================================

/// Describes how to construct execution traces of stack-related auxiliary trace segment columns
/// (used in multiset checks).
pub struct AuxTraceBuilder {
    /// A list of all rows that were added to and then removed from the overflow table.
    pub(super) overflow_table_rows: Vec<OverflowTableRow>,
    /// The number of rows in the overflow table when execution begins.
    pub(super) num_init_rows: usize,
}

impl AuxTraceBuilder {
    /// Builds and returns stack auxiliary trace columns. Currently this consists of a single
    /// column p1 describing states of the stack overflow table.
    pub fn build_aux_columns<E: FieldElement<BaseField = Felt>>(
        &self,
        main_trace: &ColMatrix<Felt>,
        rand_elements: &[E],
    ) -> Vec<Vec<E>> {
        let p1 = self.build_aux_column(main_trace, rand_elements);
        vec![p1]
    }
}

impl<E: FieldElement<BaseField = Felt>> AuxColumnBuilder<E> for AuxTraceBuilder {
    fn init_responses(&self, _main_trace: &MainTrace, alphas: &[E]) -> E {
        init_overflow_table(self, alphas)
    }
    fn get_requests_at(&self, main_trace: &MainTrace, alphas: &[E], i: usize) -> E {
        stack_overflow_table_removals(main_trace, alphas, i)
    }

    fn get_responses_at(&self, main_trace: &MainTrace, alphas: &[E], i: usize) -> E {
        stack_overflow_table_inclusions(main_trace, alphas, i)
    }
}

/// Initializes the overflow stack auxiliary column.
fn init_overflow_table<E>(overflow_table: &AuxTraceBuilder, alphas: &[E]) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    let mut initial_column_value = E::ONE;
    for row in overflow_table.overflow_table_rows.iter().take(overflow_table.num_init_rows) {
        let value = (*row).to_value(alphas);
        initial_column_value *= value;
    }
    initial_column_value
}

/// Adds a row to the stack overflow table.
fn stack_overflow_table_inclusions<E>(main_trace: &MainTrace, alphas: &[E], i: usize) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    let is_right_shift = main_trace.is_right_shift(i);

    if is_right_shift {
        let k0 = main_trace.clk(i);
        let s15 = main_trace.stack_element(15, i);
        let b1 = main_trace.parent_overflow_address(i);

        alphas[0] + alphas[1].mul_base(k0) + alphas[2].mul_base(s15) + alphas[3].mul_base(b1)
    } else {
        E::ONE
    }
}

/// Removes a row from the stack overflow table.
fn stack_overflow_table_removals<E>(main_trace: &MainTrace, alphas: &[E], i: usize) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    let is_left_shift = main_trace.is_left_shift(i);
    let is_non_empty_overflow = main_trace.is_non_empty_overflow(i);

    if is_left_shift && is_non_empty_overflow {
        let b1 = main_trace.parent_overflow_address(i);
        let s15_prime = main_trace.stack_element(15, i + 1);
        let b1_prime = main_trace.parent_overflow_address(i + 1);

        alphas[0]
            + alphas[1].mul_base(b1)
            + alphas[2].mul_base(s15_prime)
            + alphas[3].mul_base(b1_prime)
    } else {
        E::ONE
    }
}
