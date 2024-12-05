use processor::{crypto::MerkleStore, Digest};
use test_utils::{crypto::rpo_stark::SecretKey, rand::rand_vector};
use vm_core::{Felt, Word};

#[test]
fn rpo_stark_sig_execution() {
    let source = "
    use.std::crypto::dsa::rpo_stark::verifier

    begin
        exec.verifier::verify
    end
    ";

    let sk_inner = rand_vector::<Felt>(4).try_into().unwrap();
    let sk = SecretKey::from_word(sk_inner);
    let pk = sk.compute_public_key();

    let to_adv_map = sk_inner.to_vec();
    let advice_map: Vec<(Digest, Vec<Felt>)> = vec![(pk.inner().into(), to_adv_map)];

    let message: Word = rand_vector::<Felt>(4).try_into().unwrap();
    let mut op_stack = message.into_iter().map(|a| a.as_int()).collect::<Vec<u64>>();
    op_stack.extend_from_slice(&pk.inner().iter().map(|a| a.as_int()).collect::<Vec<u64>>());

    let store = MerkleStore::new();
    let test = build_test!(source, &op_stack, &[], store, advice_map);
    test.expect_stack(&[])
}
