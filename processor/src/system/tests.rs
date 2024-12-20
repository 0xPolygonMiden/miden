use crate::{DefaultHost, ExecutionOptions, Kernel, Operation, Process, StackInputs};

// Check that process returns an error if a maximum number of cycles is exceeded.
#[test]
fn cycles_num_exceeded() {
    let stack = StackInputs::default();
    let mut host = DefaultHost::default();
    let mut process = Process::new(
        Kernel::default(),
        stack,
        ExecutionOptions::new(Some(64), 64, false, false).unwrap(),
    );
    for _ in 0..64 {
        process.execute_op(Operation::Noop, &mut host).unwrap();
    }
    assert!(process.execute_op(Operation::Noop, &mut host).is_err());
}
