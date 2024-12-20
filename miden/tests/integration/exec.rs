use assembly::Assembler;
use miden_vm::DefaultHost;
use processor::{ExecutionOptions, MastForest};
use prover::{Digest, StackInputs};
use vm_core::{assert_matches, Program, ONE};

#[test]
fn advice_map_loaded_before_execution() {
    let source = "\
    begin
        push.1.1.1.1
        adv.push_mapval
        dropw
    end";

    // compile and execute program
    let program_without_advice_map: Program =
        Assembler::default().assemble_program(source).unwrap();

    // Test `processor::execute` fails if no advice map provided with the program
    let mut host = DefaultHost::default();
    match processor::execute(
        &program_without_advice_map,
        StackInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    ) {
        Ok(_) => panic!("Expected error"),
        Err(e) => {
            assert_matches!(e, prover::ExecutionError::AdviceMapKeyNotFound(_));
        },
    }

    // Test `processor::execute` works if advice map provided with the program
    let mast_forest: MastForest = (**program_without_advice_map.mast_forest()).clone();

    let key = Digest::new([ONE, ONE, ONE, ONE]);
    let value = vec![ONE, ONE];

    let mut mast_forest = mast_forest.clone();
    mast_forest.advice_map_mut().insert(key, value);
    let program_with_advice_map =
        Program::new(mast_forest.into(), program_without_advice_map.entrypoint());

    let mut host = DefaultHost::default();
    processor::execute(
        &program_with_advice_map,
        StackInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    )
    .unwrap();
}
