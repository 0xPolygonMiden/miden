use std::vec;

use assembly::{utils::Serializable, Assembler};
use miden_air::{Felt, ProvingOptions, RowIndex};
use miden_stdlib::StdLibrary;
use processor::{
    crypto::RpoRandomCoin, AdviceInputs, DefaultHost, Digest, ExecutionError, MemAdviceProvider,
    Program, ProgramInfo, StackInputs,
};
use rand::{thread_rng, Rng};
use test_utils::{
    crypto::{
        rpo_falcon512::{Polynomial, SecretKey},
        MerkleStore, Rpo256,
    },
    expect_exec_error_matches,
    rand::{rand_value, rand_vector},
    FieldElement, QuadFelt, Word, WORD_SIZE,
};

/// Modulus used for rpo falcon 512.
const M: u64 = 12289;
const Q: u64 = (M - 1) / 2;
const N: usize = 512;
const J: u64 = (N * M as usize * M as usize) as u64;

const PROBABILISTIC_PRODUCT_SOURCE: &str = "
    use.std::crypto::dsa::rpo_falcon512

    begin
        #=> [PK, ...]
        mem_load.0
        #=> [h_ptr, PK, ...]

        exec.rpo_falcon512::load_h_s2_and_product
        #=> [tau1, tau0, tau_ptr, ...]

        exec.rpo_falcon512::powers_of_tau
        #=> [zeros_ptr, ...]

        exec.rpo_falcon512::set_to_zero
        #=> [c_ptr, ...]

        drop
        #=> [...]

        push.512    # tau_ptr
        push.1025   # z_ptr
        push.0      # h ptr

        #=> [h_ptr, zeros_ptr, tau_ptr, ...]

        exec.rpo_falcon512::probabilistic_product
    end
    ";

#[test]
fn test_falcon512_norm_sq() {
    let source = "
    use.std::crypto::dsa::rpo_falcon512

    begin
        exec.rpo_falcon512::norm_sq
    end
    ";

    // normalize(e) = e^2 - phi * (2*q*e - q^2) where phi := (e > (q - 1)/2)
    let upper = rand::thread_rng().gen_range(Q + 1..M);
    let test_upper = build_test!(source, &[upper]);
    test_upper.expect_stack(&[(M - upper) * (M - upper)]);

    let lower = rand::thread_rng().gen_range(0..=Q);
    let test_lower = build_test!(source, &[lower]);
    test_lower.expect_stack(&[lower * lower])
}

#[test]
fn test_falcon512_diff_mod_q() {
    let source = "
    use.std::crypto::dsa::rpo_falcon512

    begin
        exec.rpo_falcon512::diff_mod_q
    end
    ";

    let u = rand::thread_rng().gen_range(0..J);
    let v = rand::thread_rng().gen_range(Q..M);
    let w = rand::thread_rng().gen_range(0..J);

    let test1 = build_test!(source, &[u, v, w]);

    // Calculating (v - (u + (- w % q) % q) % q) should be the same as (v + w + J - u) % q.
    let expanded_answer = (v as i64
        - (u as i64 + -(w as i64).rem_euclid(M as i64)).rem_euclid(M as i64))
    .rem_euclid(M as i64);
    let simplified_answer = (v + w + J - u).rem_euclid(M);
    assert_eq!(expanded_answer, i64::try_from(simplified_answer).unwrap());

    test1.expect_stack(&[simplified_answer]);
}

#[test]
fn test_falcon512_powers_of_tau() {
    let source = "
    use.std::crypto::dsa::rpo_falcon512

    begin
        exec.rpo_falcon512::powers_of_tau
    end
    ";

    // Compute powers of a quadratic field element from 0 to 512.
    let tau = rand_value::<QuadFelt>();
    let tau_ptr = 0_u32;
    let (tau_0, tau_1) = ext_element_to_ints(tau);

    let expected_memory = powers_of_tau(tau);
    let stack_init = [tau_ptr.into(), tau_0, tau_1];

    let test = build_test!(source, &stack_init);
    let expected_stack = &[<u32 as Into<u64>>::into(tau_ptr) + N as u64 + 1];
    test.expect_stack_and_memory(expected_stack, tau_ptr, &expected_memory);
}

#[test]
fn test_falcon512_probabilistic_product() {
    // Create two random polynomials and multiply them.
    let h = Polynomial::new(random_coefficients());
    let s2 = Polynomial::new(random_coefficients());

    let pi = mul_modulo_p(h.clone(), s2.clone());

    // Lay the polynomials in the advice stack, h then s2 then pi = h * s2.
    let mut h_array = to_elements(h.clone());
    h_array.extend(to_elements(s2.clone()));
    h_array.extend(pi.iter().map(|a| Felt::new(*a)));
    let advice_stack: Vec<u64> = h_array.iter().map(|&e| e.into()).collect();

    // Compute hash of h and place it on the stack.
    let binding = Rpo256::hash_elements(&to_elements(h.clone()));
    let h_hash = binding.as_elements();
    let h_hash_copy: Vec<u64> = h_hash.iter().map(|felt| (*felt).into()).collect();
    let stack_init = vec![h_hash_copy[0], h_hash_copy[1], h_hash_copy[2], h_hash_copy[3]];

    let test = build_test!(PROBABILISTIC_PRODUCT_SOURCE, &stack_init, &advice_stack);
    let expected_stack = &[];
    test.expect_stack(expected_stack);
}

#[test]
fn test_falcon512_probabilistic_product_failure() {
    // Create a polynomial pi that is not equal to h * s2.
    let h: Polynomial<Felt> = Polynomial::new(random_coefficients());
    let s2: Polynomial<Felt> = Polynomial::new(random_coefficients());
    let h_wrong: Polynomial<Felt> = Polynomial::new(random_coefficients());

    let pi = mul_modulo_p(h_wrong.clone(), s2.clone());

    // Lay the polynomials in the advice stack, h then s2 then pi = h_wrong * s2.
    let mut h_array = to_elements(h.clone());
    h_array.extend(to_elements(s2.clone()));
    h_array.extend(pi.iter().map(|a| Felt::new(*a)));
    let advice_stack: Vec<u64> = h_array.iter().map(|&e| e.into()).collect();

    // Compute hash of h and place it on the stack.
    let binding = Rpo256::hash_elements(&to_elements(h.clone()));
    let h_hash = binding.as_elements();
    let h_hash_copy: Vec<u64> = h_hash.iter().map(|felt| (*felt).into()).collect();

    let stack_init = vec![h_hash_copy[0], h_hash_copy[1], h_hash_copy[2], h_hash_copy[3]];
    let test = build_test!(PROBABILISTIC_PRODUCT_SOURCE, &stack_init, &advice_stack);

    expect_exec_error_matches!(
        test,
        ExecutionError::FailedAssertion{ clk, err_code, err_msg }
        if clk == RowIndex::from(17490) && err_code == 0 && err_msg.is_none()
    );
}

#[test]
fn falcon_execution() {
    let seed = Word::default();
    let mut rng = RpoRandomCoin::new(seed);
    let sk = SecretKey::with_rng(&mut rng);
    let message = rand_vector::<Felt>(4).try_into().unwrap();
    let (source, op_stack, adv_stack, store, advice_map) = generate_test(sk, message);

    let test = build_test!(source, &op_stack, &adv_stack, store, advice_map.into_iter());
    test.expect_stack(&[])
}

#[test]
#[ignore]
fn falcon_prove_verify() {
    let sk = SecretKey::new();
    let message = rand_vector::<Felt>(4).try_into().unwrap();
    let (source, op_stack, _, _, advice_map) = generate_test(sk, message);

    let program: Program = Assembler::default()
        .with_library(StdLibrary::default())
        .expect("failed to load stdlib")
        .assemble_program(source)
        .expect("failed to compile test source");

    let stack_inputs = StackInputs::try_from_ints(op_stack).expect("failed to create stack inputs");
    let advice_inputs = AdviceInputs::default().with_map(advice_map);
    let advice_provider = MemAdviceProvider::from(advice_inputs);
    let mut host = DefaultHost::new(advice_provider);

    let options = ProvingOptions::with_96_bit_security(false);
    let (stack_outputs, proof) =
        test_utils::prove(&program, stack_inputs.clone(), &mut host, options)
            .expect("failed to generate proof");

    let program_info = ProgramInfo::from(program);
    let result = test_utils::verify(program_info, stack_inputs, stack_outputs, proof);

    assert!(result.is_ok(), "error: {result:?}");
}

#[allow(clippy::type_complexity)]
fn generate_test(
    sk: SecretKey,
    message: Word,
) -> (&'static str, Vec<u64>, Vec<u64>, MerkleStore, Vec<(Digest, Vec<Felt>)>) {
    let source = "
    use.std::crypto::dsa::rpo_falcon512

    begin
        exec.rpo_falcon512::verify
    end
    ";

    let pk: Word = sk.public_key().into();
    let pk: Digest = pk.into();
    let sk_bytes = sk.to_bytes();

    let to_adv_map = sk_bytes.iter().map(|a| Felt::new(*a as u64)).collect::<Vec<Felt>>();

    let advice_map: Vec<(Digest, Vec<Felt>)> = vec![(pk, to_adv_map)];

    let mut op_stack = vec![];
    let message = message.into_iter().map(|a| a.as_int()).collect::<Vec<u64>>();
    op_stack.extend_from_slice(&message);
    op_stack.extend_from_slice(&pk.as_elements().iter().map(|a| a.as_int()).collect::<Vec<u64>>());
    let adv_stack = vec![];
    let store = MerkleStore::new();

    (source, op_stack, adv_stack, store, advice_map)
}

// HELPER FUNCTIONS
// ================================================================================================
// Helper function to convert a quadratic extension field element into a tuple of elements in the
// underlying base field and convert them into integers.
fn ext_element_to_ints(ext_elem: QuadFelt) -> (u64, u64) {
    let base_elements = ext_elem.to_base_elements();
    (base_elements[0].as_int(), base_elements[1].as_int())
}

/*
    For an element `tau := (tau0, tau1)` in the quadratic extension field, computes all its powers
    `tau^i` for `i = 0,..., 512` and stores them in a vector of length 2048 (word size * 512).  The
    first two field elements of the ith word are the elements of tau^i, and the second two field
    elements are the previous power of tau, tau^(i - 1).  Used to test powers of tau procedure.
    Example:
    [1, 0, 0, 0, tau_0, tau_1, 1, 0, (tau^2)_0, (tau^2)_1, tau_0, tau_1, (tau^3)_0, (tau^3)_1,
    (tau^2)_0, (tau^2)_1, ...]
*/

fn powers_of_tau(tau: QuadFelt) -> Vec<u64> {
    let mut tau_power: QuadFelt;
    let mut elem_0: u64;
    let mut elem_1: u64;
    let mut expected_memory = vec![0; (N + 1) * WORD_SIZE];
    expected_memory[0] = 1;

    for i in 1..N + 1 {
        tau_power = tau.exp(i as u64);
        (elem_0, elem_1) = ext_element_to_ints(tau_power);
        expected_memory[i * WORD_SIZE] = elem_0;
        expected_memory[i * WORD_SIZE + 1] = elem_1;
        expected_memory[i * WORD_SIZE + 2] = expected_memory[i * WORD_SIZE - WORD_SIZE];
        expected_memory[i * WORD_SIZE + 3] = expected_memory[i * WORD_SIZE - 3];
    }
    expected_memory
}

// Create random coefficients in the range of a polynomial in M.
fn random_coefficients() -> Vec<Felt> {
    let mut res = Vec::new();
    for _i in 0..N {
        res.push(Felt::new(thread_rng().gen_range(0..M)))
    }
    res
}

/* Multiplies two polynomials over Z_p\[x\] without reducing modulo p. Given that the degrees
of the input polynomials are less than 512 and their coefficients are less than the modulus
q equal to M = 12289, the resulting product polynomial is guaranteed to have coefficients less
than the Miden prime.
Note that this multiplication is not over Z_p\[x\]/(phi).
*/
pub fn mul_modulo_p(a: Polynomial<Felt>, b: Polynomial<Felt>) -> [u64; 1024] {
    let mut c = [0; 2 * N];
    for i in 0..N {
        for j in 0..N {
            c[i + j] += a.coefficients[i].as_int() * b.coefficients[j].as_int();
        }
    }
    c
}

pub fn to_elements(poly: Polynomial<Felt>) -> Vec<Felt> {
    poly.coefficients.to_vec()
}
