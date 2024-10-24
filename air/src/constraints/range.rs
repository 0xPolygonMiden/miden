use alloc::vec::Vec;

use vm_core::{Felt, ZERO};

use crate::{
    trace::range::V_COL_IDX, Assertion, EvaluationFrame, FieldElement, TransitionConstraintDegree,
};

// CONSTANTS
// ================================================================================================

// --- Main constraints ---------------------------------------------------------------------------

/// The number of boundary constraints required by the Range Checker
pub const NUM_ASSERTIONS: usize = 2;
/// The number of transition constraints required by the Range Checker.
pub const NUM_CONSTRAINTS: usize = 1;
/// The degrees of the range checker's constraints, in the order they'll be added to the the result
/// array when a transition is evaluated.
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    9, // Enforce values of column v transition.
];

// BOUNDARY CONSTRAINTS
// ================================================================================================

// --- MAIN TRACE ---------------------------------------------------------------------------------

/// Returns the range checker's boundary assertions for the main trace at the first step.
pub fn get_assertions_first_step(result: &mut Vec<Assertion<Felt>>) {
    let step = 0;
    result.push(Assertion::single(V_COL_IDX, step, ZERO));
}

/// Returns the range checker's boundary assertions for the main trace at the last step.
pub fn get_assertions_last_step(result: &mut Vec<Assertion<Felt>>, step: usize) {
    result.push(Assertion::single(V_COL_IDX, step, Felt::new(65535)));
}

// TRANSITION CONSTRAINTS
// ================================================================================================

// --- MAIN TRACE ---------------------------------------------------------------------------------

/// Builds the transition constraint degrees for the range checker.
pub fn get_transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    CONSTRAINT_DEGREES
        .iter()
        .map(|&degree| TransitionConstraintDegree::new(degree))
        .collect()
}

/// Returns the number of transition constraints for the range checker.
pub fn get_transition_constraint_count() -> usize {
    NUM_CONSTRAINTS
}

/// Enforces constraints for the range checker.
pub fn enforce_constraints<E: FieldElement>(frame: &EvaluationFrame<E>, result: &mut [E]) {
    // Constrain the transition of the value column between rows in the range checker table.
    result[0] = frame.change(V_COL_IDX)
        * (frame.change(V_COL_IDX) - E::ONE)
        * (frame.change(V_COL_IDX) - E::from(3_u8))
        * (frame.change(V_COL_IDX) - E::from(9_u8))
        * (frame.change(V_COL_IDX) - E::from(27_u8))
        * (frame.change(V_COL_IDX) - E::from(81_u8))
        * (frame.change(V_COL_IDX) - E::from(243_u8))
        * (frame.change(V_COL_IDX) - E::from(729_u16))
        * (frame.change(V_COL_IDX) - E::from(2187_u16));
}

// RANGE CHECKER FRAME EXTENSION TRAIT
// ================================================================================================

/// Trait to allow easy access to column values and intermediate variables used in constraint
/// calculations for the Range Checker.
trait EvaluationFrameExt<E: FieldElement> {
    // --- Intermediate variables & helpers -------------------------------------------------------

    /// The change between the current value in the specified column and the next value, calculated
    /// as `next - current`.
    fn change(&self, column: usize) -> E;
}

impl<E: FieldElement> EvaluationFrameExt<E> for &EvaluationFrame<E> {
    // --- Intermediate variables & helpers -------------------------------------------------------

    #[inline(always)]
    fn change(&self, column: usize) -> E {
        self.next()[column] - self.current()[column]
    }
}
