use std::{borrow::ToOwned, vec::Vec};

use channel::VerifierChannel;
use verifier::VerifierError;
use vm_core::{
    crypto::{
        dsa::rpo_stark::RescueAir,
        hash::{Rpo256, RpoDigest},
        merkle::MerkleStore,
        random::{RandomCoin, RpoRandomCoin},
    },
    Felt, FieldElement, QuadExtension, StarkField, ToElements,
};
use winter_fri::VerifierChannel as FriVerifierChannel;
use winter_prover::{math::fft, Air, ConstraintCompositionCoefficients, Proof};

use super::SignatureData;

mod channel;

pub const BLOWUP_FACTOR: usize = 8;
pub type QuadExt = QuadExtension<Felt>;

pub fn generate_advice_inputs_signature(
    proof: Proof,
    pub_inputs: <RescueAir as Air>::PublicInputs,
) -> Result<SignatureData, VerifierError> {
    // build a seed for the public coin; the initial seed is the hash of public inputs and proof
    // context, but as the protocol progresses, the coin will be reseeded with the info received
    // from the prover
    let mut tape = vec![];
    let mut public_coin_seed = proof.context.to_elements();

    public_coin_seed.append(&mut pub_inputs.to_elements());

    // create AIR instance for the computation specified in the proof
    let air = RescueAir::new(proof.trace_info().to_owned(), pub_inputs, proof.options().clone());
    let seed_digest = Rpo256::hash_elements(&public_coin_seed);
    let mut public_coin: RpoRandomCoin = RpoRandomCoin::new(seed_digest.into());
    let mut channel = VerifierChannel::new(&air, proof)?;
    let mut fs_salts = channel.read_salts();

    // 1 ----- main segment trace -----------------------------------------------------------------
    let trace_commitments = channel.read_trace_commitments();

    // reseed the coin with the commitment to the main segment trace
    let fs_salt = fs_salts.remove(0);
    public_coin.reseed_with_salt(trace_commitments[0], fs_salt);
    tape.extend_from_slice(&digest_to_int_vec(trace_commitments));
    tape.extend_from_slice(&digest_to_int_vec(&[fs_salt.unwrap()]));

    // 2 ----- constraint composition trace -------------------------------------------------------

    // build random coefficients for the composition polynomial. we don't need them but we have to
    // generate them in order to update the random coin
    let _constraint_coeffs: ConstraintCompositionCoefficients<QuadExt> = air
        .get_constraint_composition_coefficients(&mut public_coin)
        .map_err(|_| VerifierError::RandomCoinError)?;
    let constraint_commitment = channel.read_constraint_commitment();
    let fs_salt = fs_salts.remove(0);
    public_coin.reseed_with_salt(constraint_commitment, fs_salt);
    tape.extend_from_slice(&digest_to_int_vec(&[constraint_commitment]));
    tape.extend_from_slice(&digest_to_int_vec(&[fs_salt.unwrap()]));

    // 3 ----- OOD frames --------------------------------------------------------------

    // generate the the OOD point
    let _z: QuadExt = public_coin.draw().unwrap();

    // read the main and auxiliary segments' OOD frames and add them to advice tape
    let ood_trace_frame = channel.read_ood_trace_frame();
    let _ood_main_trace_frame = ood_trace_frame.main_frame();
    let _ood_aux_trace_frame = ood_trace_frame.aux_frame();

    let mut main_frame_states = Vec::new();
    for col in 0.._ood_main_trace_frame.current().len() {
        main_frame_states.push(_ood_main_trace_frame.current()[col]);
        main_frame_states.push(_ood_main_trace_frame.next()[col]);
    }

    let fs_salt = fs_salts.remove(0);
    public_coin.reseed_with_salt(Rpo256::hash_elements(&main_frame_states), fs_salt);
    tape.extend_from_slice(&to_int_vec(&main_frame_states));
    tape.extend_from_slice(&digest_to_int_vec(&[fs_salt.unwrap()]));

    // read OOD evaluations of composition polynomial columns
    let ood_constraint_evaluations = channel.read_ood_constraint_evaluations();
    let fs_salt = fs_salts.remove(0);
    public_coin.reseed_with_salt(Rpo256::hash_elements(&ood_constraint_evaluations), fs_salt);
    tape.extend_from_slice(&to_int_vec(&ood_constraint_evaluations));
    tape.extend_from_slice(&digest_to_int_vec(&[fs_salt.unwrap()]));
    assert!(fs_salts.is_empty());

    // 4 ----- FRI  -------------------------------------------------------------------------------

    // read the FRI layer committments as well as remainder polynomial
    let fri_commitments_digests = channel.read_fri_layer_commitments();
    let mut salts = channel.read_fri_salts();
    let poly = channel.read_remainder().unwrap();

    // Reed-Solomon encode the remainder polynomial as this is needed for the probabilistic NTT
    let twiddles = fft::get_twiddles(poly.len());
    let fri_remainder =
        fft::evaluate_poly_with_offset(&poly, &twiddles, Felt::GENERATOR, BLOWUP_FACTOR);

    let fri_commitments_and_salts: Vec<RpoDigest> = fri_commitments_digests
        .iter()
        .zip(salts.iter())
        .flat_map(|(com, salt)| [*com, salt.unwrap()])
        .collect();
    // add the above to the advice tape
    let fri_commitments: Vec<u64> = digest_to_int_vec(&fri_commitments_and_salts);
    tape.extend_from_slice(&fri_commitments);
    tape.extend_from_slice(&to_int_vec(&poly));
    tape.extend_from_slice(&to_int_vec(&fri_remainder));

    // reseed with FRI layer commitments
    let _deep_coefficients = air
        .get_deep_composition_coefficients::<QuadExt, RpoRandomCoin>(&mut public_coin)
        .map_err(|_| VerifierError::RandomCoinError)?;
    let layer_commitments = fri_commitments_digests.clone();
    for commitment in layer_commitments.iter() {
        let salt = salts.remove(0);
        public_coin.reseed_with_salt(*commitment, salt);
        let _alpha: QuadExt = public_coin.draw().expect("failed to draw random indices");
    }

    // 5 ----- trace and constraint queries -------------------------------------------------------

    // read proof-of-work nonce sent by the prover and draw pseudo-random query positions for
    // the LDE domain from the public coin
    let pow_nonce = channel.read_pow_nonce();
    let mut query_positions = public_coin
        .draw_integers(air.options().num_queries(), air.lde_domain_size(), pow_nonce)
        .map_err(|_| VerifierError::RandomCoinError)?;
    tape.extend_from_slice(&[pow_nonce]);
    query_positions.sort();
    query_positions.dedup();

    // read advice maps and Merkle paths of the queries to main/aux and constraint composition
    // traces
    let (mut main_aux_adv_map, mut partial_trees_traces) =
        channel.read_queried_trace_states(&query_positions)?;
    let (mut constraint_adv_map, partial_tree_constraint) =
        channel.read_constraint_evaluations(&query_positions)?;
    let (mut partial_trees_fri, mut fri_adv_map) = channel.unbatch_fri_layer_proofs::<4>(
        &query_positions,
        air.lde_domain_size(),
        fri_commitments_digests,
    );

    // consolidate advice maps
    main_aux_adv_map.append(&mut constraint_adv_map);
    main_aux_adv_map.append(&mut fri_adv_map);

    // build the full MerkleStore
    partial_trees_fri.append(&mut partial_trees_traces);
    partial_trees_fri.push(partial_tree_constraint);
    let mut store = MerkleStore::new();
    for partial_tree in &partial_trees_fri {
        store.extend(partial_tree.inner_nodes());
    }

    let advice_stack = tape.iter().map(|v| Felt::new(*v)).collect();
    Ok(SignatureData {
        advice_stack,
        store: Some(store),
        advice_map: Some(main_aux_adv_map),
    })
}

// HELPER FUNCTIONS
// ================================================================================================

pub fn digest_to_int_vec(digest: &[RpoDigest]) -> Vec<u64> {
    digest
        .iter()
        .flat_map(|digest| digest.as_elements().iter().map(|e| e.as_int()))
        .collect()
}

pub fn to_int_vec(ext_felts: &[QuadExt]) -> Vec<u64> {
    QuadExt::slice_as_base_elements(ext_felts).iter().map(|e| e.as_int()).collect()
}
