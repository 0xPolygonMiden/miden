use processor::{ContextId, DefaultHost, Program};
use test_utils::{
    build_expected_hash, build_expected_perm, felt_slice_to_ints, ExecutionOptions, Process,
    StackInputs, ONE, ZERO,
};

#[test]
fn test_memcopy() {
    use miden_stdlib::StdLibrary;

    let source = "
    use.std::mem

    begin
        push.0.0.0.1.1000 mem_storew dropw
        push.0.0.1.0.1001 mem_storew dropw
        push.0.0.1.1.1002 mem_storew dropw
        push.0.1.0.0.1003 mem_storew dropw
        push.0.1.0.1.1004 mem_storew dropw

        push.2000.1000.5 exec.mem::memcopy
    end
    ";

    let stdlib = StdLibrary::default();
    let assembler = assembly::Assembler::default()
        .with_library(&stdlib)
        .expect("failed to load stdlib");

    let program: Program =
        assembler.assemble_program(source).expect("Failed to compile test source.");

    let mut host = DefaultHost::default();
    host.load_mast_forest(stdlib.mast_forest().clone()).unwrap();

    let mut process =
        Process::new(program.kernel().clone(), StackInputs::default(), ExecutionOptions::default());
    process.execute(&program, &mut host).unwrap();

    assert_eq!(
        process.chiplets.get_mem_value(ContextId::root(), 1000),
        Some([ZERO, ZERO, ZERO, ONE]),
        "Address 1000"
    );
    assert_eq!(
        process.chiplets.get_mem_value(ContextId::root(), 1001),
        Some([ZERO, ZERO, ONE, ZERO]),
        "Address 1001"
    );
    assert_eq!(
        process.chiplets.get_mem_value(ContextId::root(), 1002),
        Some([ZERO, ZERO, ONE, ONE]),
        "Address 1002"
    );
    assert_eq!(
        process.chiplets.get_mem_value(ContextId::root(), 1003),
        Some([ZERO, ONE, ZERO, ZERO]),
        "Address 1003"
    );
    assert_eq!(
        process.chiplets.get_mem_value(ContextId::root(), 1004),
        Some([ZERO, ONE, ZERO, ONE]),
        "Address 1004"
    );

    assert_eq!(
        process.chiplets.get_mem_value(ContextId::root(), 2000),
        Some([ZERO, ZERO, ZERO, ONE]),
        "Address 2000"
    );
    assert_eq!(
        process.chiplets.get_mem_value(ContextId::root(), 2001),
        Some([ZERO, ZERO, ONE, ZERO]),
        "Address 2001"
    );
    assert_eq!(
        process.chiplets.get_mem_value(ContextId::root(), 2002),
        Some([ZERO, ZERO, ONE, ONE]),
        "Address 2002"
    );
    assert_eq!(
        process.chiplets.get_mem_value(ContextId::root(), 2003),
        Some([ZERO, ONE, ZERO, ZERO]),
        "Address 2003"
    );
    assert_eq!(
        process.chiplets.get_mem_value(ContextId::root(), 2004),
        Some([ZERO, ONE, ZERO, ONE]),
        "Address 2004"
    );
}

#[test]
fn test_pipe_double_words_to_memory() {
    let mem_addr = 1000;
    let source = format!(
        "
        use.std::mem
        use.std::sys

        begin
            push.1002       # end_addr
            push.{}         # write_addr
            padw padw padw  # hasher state

            exec.mem::pipe_double_words_to_memory

            exec.sys::truncate_stack
        end",
        mem_addr
    );

    let operand_stack = &[];
    let data = &[1, 2, 3, 4, 5, 6, 7, 8];
    let mut expected_stack =
        felt_slice_to_ints(&build_expected_perm(&[0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]));
    expected_stack.push(1002);
    build_test!(source, operand_stack, &data).expect_stack_and_memory(
        &expected_stack,
        mem_addr,
        data,
    );
}

#[test]
fn test_pipe_words_to_memory() {
    let mem_addr = 1000;
    let one_word = format!(
        "
        use.std::mem
        use.std::crypto::hashes::rpo

        begin
            push.{} # target address
            push.1  # number of words

            exec.mem::pipe_words_to_memory
            exec.rpo::squeeze_digest

            # truncate stack
            swapdw dropw dropw
        end",
        mem_addr
    );

    let operand_stack = &[];
    let data = &[1, 2, 3, 4];
    let mut expected_stack = felt_slice_to_ints(&build_expected_hash(data));
    expected_stack.push(1001);
    build_test!(one_word, operand_stack, &data).expect_stack_and_memory(
        &expected_stack,
        mem_addr,
        data,
    );

    let three_words = format!(
        "
        use.std::mem
        use.std::crypto::hashes::rpo

        begin
            push.{} # target address
            push.3  # number of words

            exec.mem::pipe_words_to_memory
            exec.rpo::squeeze_digest

            # truncate stack
            swapdw dropw dropw
        end",
        mem_addr
    );

    let operand_stack = &[];
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut expected_stack = felt_slice_to_ints(&build_expected_hash(data));
    expected_stack.push(1003);
    build_test!(three_words, operand_stack, &data).expect_stack_and_memory(
        &expected_stack,
        mem_addr,
        data,
    );
}

#[test]
fn test_pipe_preimage_to_memory() {
    let mem_addr = 1000;
    let three_words = format!(
        "use.std::mem

        begin
            adv_push.4 # push commitment to stack
            push.{}    # target address
            push.3     # number of words

            exec.mem::pipe_preimage_to_memory
            swap drop
        end",
        mem_addr
    );

    let operand_stack = &[];
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut advice_stack = felt_slice_to_ints(&build_expected_hash(data));
    advice_stack.reverse();
    advice_stack.extend(data);
    build_test!(three_words, operand_stack, &advice_stack).expect_stack_and_memory(
        &[1003],
        mem_addr,
        data,
    );
}

#[test]
fn test_pipe_preimage_to_memory_invalid_preimage() {
    let three_words = "
    use.std::mem

    begin
        adv_push.4  # push commitment to stack
        push.1000   # target address
        push.3      # number of words

        exec.mem::pipe_preimage_to_memory
    end
    ";

    let operand_stack = &[];
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut advice_stack = felt_slice_to_ints(&build_expected_hash(data));
    advice_stack.reverse();
    advice_stack[0] += 1; // corrupt the expected hash
    advice_stack.extend(data);
    let res = build_test!(three_words, operand_stack, &advice_stack).execute();
    assert!(res.is_err());
}
