use crate::trace::MIN_TRACE_LEN;

// EXECUTION OPTIONS ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum ExecutionOptionsError {
    #[error("expected number of cycles {expected_cycles} must be smaller than the maximum number of cycles {max_cycles}")]
    ExpectedCyclesTooBig { max_cycles: u32, expected_cycles: u32 },
    #[error("maximum number of cycles {0} must be greater than the minimum number of cycles {MIN_TRACE_LEN}")]
    MaxCycleNumTooSmall(u32),
}
