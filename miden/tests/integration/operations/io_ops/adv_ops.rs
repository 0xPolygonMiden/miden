use super::{build_op_test, build_test, TestError};
use vm_core::{chiplets::hasher::apply_permutation, utils::ToElements, Felt, StarkField};

// PUSHING VALUES ONTO THE STACK (PUSH)
// ================================================================================================

#[test]
fn adv_pop() {
    let asm_op = "adv_pop";
    let advice_stack = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let test_n = |n: usize| {
        let source = format!("{asm_op}.{n}");
        let mut final_stack = vec![0; n];
        final_stack.copy_from_slice(&advice_stack[..n]);
        final_stack.reverse();

        let test = build_op_test!(source, &[], &advice_stack);
        test.expect_stack(&final_stack);
    };

    // --- push 1 ---------------------------------------------------------------------------------
    test_n(1);

    // --- push max -------------------------------------------------------------------------------
    test_n(16);
}

#[test]
fn adv_pop_invalid() {
    // attempting to read from empty advice stack should throw an error
    let test = build_op_test!("adv_pop.1");
    test.expect_error(TestError::ExecutionError("AdviceStackReadFailed"));
}

// OVERWRITING VALUES ON THE STACK (LOAD)
// ================================================================================================

#[test]
fn adv_popw() {
    let asm_op = "adv_popw";
    let advice_stack = [1, 2, 3, 4];
    let mut final_stack = advice_stack;
    final_stack.reverse();

    let test = build_op_test!(asm_op, &[8, 7, 6, 5], &advice_stack);
    test.expect_stack(&final_stack);
}

#[test]
fn adv_popw_invalid() {
    // attempting to read from empty advice stack should throw an error
    let test = build_op_test!("adv_popw", &[0, 0, 0, 0]);
    test.expect_error(TestError::ExecutionError("AdviceStackReadFailed"));
}

// MOVING ELEMENTS TO MEMORY VIA THE STACK (PIPE)
// ================================================================================================

#[test]
fn adv_pipe() {
    let source = "
        begin
            push.12 push.11 push.10 push.9 push.8 push.7 push.6 push.5 push.4 push.3 push.2 push.1
            adv_pipe
        end";

    let advice_stack = [1, 2, 3, 4, 5, 6, 7, 8];

    // the state of the hasher is the first 12 elements of the stack (in reverse order). the state
    // is built by replacing the values on the top of the stack with the top 8 values from the head
    // of the advice stack (i.e. values 1 through 8). Thus, the first 8 elements on the stack will be
    // 1-8 in stack order (stack[0] = 8), and the remaining 4 are untouched (i.e., 9, 10, 11, 12).
    let mut state: [Felt; 12] =
        [12_u64, 11, 10, 9, 1, 2, 3, 4, 5, 6, 7, 8].to_elements().try_into().unwrap();

    // apply a hash permutation to the state
    apply_permutation(&mut state);

    // to get the final state of the stack, reverse the hasher state and push the expected address
    // to the end (the address will be 2 since 0 + 2 = 2).
    let mut final_stack = state.iter().map(|&v| v.as_int()).collect::<Vec<u64>>();
    final_stack.reverse();
    final_stack.push(2);

    let test = build_test!(source, &[], &advice_stack);
    test.expect_stack(&final_stack);
}
