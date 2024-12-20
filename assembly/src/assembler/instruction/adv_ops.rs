use vm_core::Operation;

use super::{validate_param, BasicBlockBuilder};
use crate::{AssemblyError, ADVICE_READ_LIMIT};

// NON-DETERMINISTIC (ADVICE) INPUTS
// ================================================================================================

/// Appends the number of ADVPOP operations specified by the instruction's immediate value to the
/// span. This pops the specified number of elements from the advice stack and pushes them onto the
/// operand stack.
///
/// # Errors
/// Returns an error if the specified number of values to pushed is smaller than 1 or greater
/// than 16.
pub fn adv_push(block_builder: &mut BasicBlockBuilder, n: u8) -> Result<(), AssemblyError> {
    validate_param(n, 1..=ADVICE_READ_LIMIT)?;
    block_builder.push_op_many(Operation::AdvPop, n as usize);
    Ok(())
}
