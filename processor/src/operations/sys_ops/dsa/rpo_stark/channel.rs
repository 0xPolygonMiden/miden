use std::{borrow::ToOwned, string::ToString, vec::Vec};

use rand_chacha::ChaCha20Rng;
use verifier::{Digest, VerifierError};
use vm_core::{
    crypto::{dsa::rpo_stark::RescueAir, hash::Rpo256, merkle::PartialMerkleTree},
    Felt, FieldElement, QuadExtension, StarkField,
};
use winter_fri::{folding::fold_positions, VerifierChannel as FriVerifierChannel};
use winter_prover::{
    crypto::{BatchMerkleProof, Hasher, SaltedMerkleTree, VectorCommitment},
    proof::{Queries, Table, TraceOodFrame},
    Air, Proof,
};
use winter_utils::{group_slice_elements, Deserializable};

pub type QuadExt = QuadExtension<Felt>;

type AdvMap = Vec<(Digest, Vec<Felt>)>;
type SaltedBatchMerkleProof<Rpo256> = (Vec<Digest>, BatchMerkleProof<Rpo256>);

/// A view into a [Proof] for a computation structured to simulate an "interactive" channel.
///
/// A channel is instantiated for a specific proof, which is parsed into structs over the
/// appropriate field (specified by type parameter `E`). This also validates that the proof is
/// well-formed in the context of the computation for the specified [Air].
pub struct VerifierChannel {
    // trace queries
    trace_roots: Vec<Digest>,
    trace_queries: Option<TraceQueries>,
    // constraint queries
    constraint_root: Digest,
    constraint_queries: Option<ConstraintQueries>,
    // FRI proof
    fri_roots: Option<Vec<Digest>>,
    fri_layer_proofs: Vec<SaltedBatchMerkleProof<Rpo256>>,
    fri_layer_queries: Vec<Vec<QuadExt>>,
    fri_remainder: Option<Vec<QuadExt>>,
    fri_num_partitions: usize,
    fri_salts: Vec<Option<Digest>>,
    // out-of-domain frame
    ood_trace_frame: Option<TraceOodFrame<QuadExt>>,
    ood_constraint_evaluations: Option<Vec<QuadExt>>,
    // query proof-of-work
    pow_nonce: u64,
    // Fiat-Shamir salts
    salts: Vec<Option<Digest>>,
}

impl VerifierChannel {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates and returns a new [VerifierChannel] initialized from the specified `proof`.
    pub fn new(air: &RescueAir, proof: Proof) -> Result<Self, VerifierError> {
        let Proof {
            context,
            commitments,
            trace_queries,
            constraint_queries,
            ood_frame,
            fri_proof,
            pow_nonce,
            num_unique_queries,
            gkr_proof: _,
            salts,
        } = proof;

        // make AIR and proof base fields are the same
        if Felt::get_modulus_le_bytes() != context.field_modulus_bytes() {
            return Err(VerifierError::InconsistentBaseField);
        }

        let num_trace_segments = air.trace_info().num_segments();
        let main_trace_width = air.trace_info().main_trace_width();
        let aux_trace_width = air.trace_info().aux_segment_width();
        let lde_domain_size = air.lde_domain_size();
        let fri_options = air.options().to_fri_options();
        let constraint_frame_width = air.context().num_constraint_composition_columns();

        // --- parse commitments ------------------------------------------------------------------
        let (trace_roots, constraint_root, fri_roots) = commitments
            .parse::<Rpo256>(num_trace_segments, fri_options.num_fri_layers(lde_domain_size))
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;
        // --- parse trace and constraint queries -------------------------------------------------
        let trace_queries = TraceQueries::new(trace_queries, air, num_unique_queries as usize)?;
        let constraint_queries =
            ConstraintQueries::new(constraint_queries, air, num_unique_queries as usize)?;

        // --- parse FRI proofs -------------------------------------------------------------------
        let fri_num_partitions = fri_proof.num_partitions();
        let fri_remainder = fri_proof
            .parse_remainder()
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        let fri_salts = fri_proof
            .parse_salts::<QuadExt, Rpo256>()
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;
        let (fri_layer_queries, fri_layer_proofs) = fri_proof
            .parse_layers::<QuadExt, Rpo256, SaltedMerkleTree<Rpo256, ChaCha20Rng>>(
                lde_domain_size,
                fri_options.folding_factor(),
            )
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        // --- parse out-of-domain evaluation frame -----------------------------------------------
        let (ood_trace_evaluations, ood_constraint_evaluations) = ood_frame
            .parse(main_trace_width, aux_trace_width, constraint_frame_width)
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        // --- parse Fiat-Shamir salts -----------------------------------------------
        let salts: Vec<Option<Digest>> = Vec::read_from_bytes(&salts)
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        Ok(VerifierChannel {
            // trace queries
            trace_roots,
            trace_queries: Some(trace_queries),
            // constraint queries
            constraint_root,
            constraint_queries: Some(constraint_queries),
            // FRI proof
            fri_roots: Some(fri_roots),
            fri_layer_proofs,
            fri_layer_queries,
            fri_remainder: Some(fri_remainder),
            fri_num_partitions,
            fri_salts,
            // out-of-domain evaluation
            ood_trace_frame: Some(ood_trace_evaluations),
            ood_constraint_evaluations: Some(ood_constraint_evaluations),
            // query seed
            pow_nonce,
            // Fiat-Shamir salts
            salts,
        })
    }

    // DATA READERS
    // --------------------------------------------------------------------------------------------

    /// Returns execution trace commitments sent by the prover.
    ///
    /// For computations requiring multiple trace segment, the returned slice will contain a
    /// commitment for each trace segment.
    pub fn read_trace_commitments(&self) -> &[Digest] {
        &self.trace_roots
    }

    /// Returns constraint evaluation commitment sent by the prover.
    pub fn read_constraint_commitment(&self) -> Digest {
        self.constraint_root
    }

    /// Returns trace polynomial evaluations at out-of-domain points z and z * g, where g is the
    /// generator of the LDE domain.
    ///
    /// For computations requiring multiple trace segments, evaluations of auxiliary trace
    /// polynomials are also included as the second value of the returned tuple. Otherwise, the
    /// second value is None.
    pub fn read_ood_trace_frame(&mut self) -> TraceOodFrame<QuadExt> {
        self.ood_trace_frame.take().expect("already read")
    }

    /// Returns evaluations of composition polynomial columns at z^m, where z is the out-of-domain
    /// point, and m is the number of composition polynomial columns.
    pub fn read_ood_constraint_evaluations(&mut self) -> Vec<QuadExt> {
        self.ood_constraint_evaluations.take().expect("already read")
    }

    /// Returns query proof-of-work nonce sent by the prover.
    pub fn read_pow_nonce(&self) -> u64 {
        self.pow_nonce
    }

    /// Returns the salts needed for Fiat-Shamir.
    pub fn read_salts(&self) -> Vec<Option<Digest>> {
        self.salts.clone()
    }

    /// Returns the salts needed for Fiat-Shamir in FRI.
    pub(crate) fn read_fri_salts(&self) -> Vec<Option<Digest>> {
        self.fri_salts.clone()
    }

    /// Returns trace states at the specified positions of the LDE domain. This also checks if
    /// the trace states are valid against the trace commitment sent by the prover.
    #[allow(clippy::type_complexity)]
    pub fn read_queried_trace_states(
        &mut self,
        positions: &[usize],
    ) -> Result<(AdvMap, Vec<PartialMerkleTree>), VerifierError> {
        let queries = self.trace_queries.take().expect("already read");
        let proofs = queries.query_proofs;
        let main_queries = queries.main_states;
        let main_queries_vec: Vec<Vec<Felt>> = main_queries.rows().map(|a| a.to_owned()).collect();

        let (main_trace_pmt, main_trace_adv_map) =
            unbatch_to_partial_mt(positions.to_vec(), main_queries_vec, proofs[0].clone());

        let trees = vec![main_trace_pmt];

        Ok((main_trace_adv_map, trees))
    }

    /// Returns constraint evaluations at the specified positions of the LDE domain. This also
    /// checks if the constraint evaluations are valid against the constraint commitment sent by
    /// the prover.
    pub fn read_constraint_evaluations(
        &mut self,
        positions: &[usize],
    ) -> Result<(AdvMap, PartialMerkleTree), VerifierError> {
        let queries = self.constraint_queries.take().expect("already read");
        let proof = queries.query_proofs;

        let queries = queries
            .evaluations
            .rows()
            .map(|a| QuadExt::slice_as_base_elements(a).into())
            .collect();
        let (constraint_pmt, constraint_adv_map) =
            unbatch_to_partial_mt(positions.to_vec(), queries, proof);

        Ok((constraint_adv_map, constraint_pmt))
    }

    /// Returns the FRI layers Merkle batch proofs.
    pub fn fri_layer_proofs(&self) -> Vec<SaltedBatchMerkleProof<Rpo256>> {
        self.fri_layer_proofs.clone()
    }

    /// Returns the unbatched Merkle proofs as well as a global key-value map for all the FRI layer
    /// proofs.
    pub fn unbatch_fri_layer_proofs<const N: usize>(
        &mut self,
        positions_: &[usize],
        domain_size: usize,
        layer_commitments: Vec<Digest>,
    ) -> (Vec<PartialMerkleTree>, Vec<(Digest, Vec<Felt>)>) {
        let all_layers_queries = self.fri_layer_queries.clone();
        let mut current_domain_size = domain_size;
        let mut positions = positions_.to_vec();
        let number_of_folds = layer_commitments.len() - 1;

        let mut global_adv_key_map = Vec::new();
        let mut global_partial_merkle_trees = Vec::new();
        let mut layer_proofs = self.fri_layer_proofs();
        for current_layer_queries in all_layers_queries.iter().take(number_of_folds) {
            let mut folded_positions = fold_positions(&positions, current_domain_size, N);

            let layer_proof = layer_proofs.remove(0);
            let queries: Vec<_> = group_slice_elements::<QuadExt, N>(current_layer_queries)
                .iter()
                .map(|query| QuadExt::slice_as_base_elements(query).to_vec())
                .collect();

            let (current_partial_merkle_tree, mut cur_adv_key_map) =
                unbatch_to_partial_mt(folded_positions.clone(), queries, layer_proof);

            global_partial_merkle_trees.push(current_partial_merkle_tree);
            global_adv_key_map.append(&mut cur_adv_key_map);

            core::mem::swap(&mut positions, &mut folded_positions);
            current_domain_size /= N;
        }

        (global_partial_merkle_trees, global_adv_key_map)
    }
}

// FRI VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

impl FriVerifierChannel<QuadExt> for VerifierChannel {
    type Hasher = Rpo256;
    type VectorCommitment = SaltedMerkleTree<Self::Hasher, ChaCha20Rng>;

    fn read_fri_num_partitions(&self) -> usize {
        self.fri_num_partitions
    }

    fn read_fri_layer_commitments(&mut self) -> Vec<Digest> {
        self.fri_roots.take().expect("already read")
    }

    fn take_next_fri_layer_proof(
        &mut self,
    ) -> <Self::VectorCommitment as VectorCommitment<Self::Hasher>>::MultiProof {
        self.fri_layer_proofs.remove(0)
    }

    fn take_next_fri_layer_queries(&mut self) -> Vec<QuadExt> {
        self.fri_layer_queries.remove(0)
    }

    fn take_fri_remainder(&mut self) -> Vec<QuadExt> {
        self.fri_remainder.take().expect("already read")
    }

    fn take_salt(&mut self) -> Option<<Self::Hasher as Hasher>::Digest> {
        self.salts.remove(0)
    }
}

// TRACE QUERIES
// ================================================================================================

/// Container of trace query data, including:
/// * Queried states for main trace segment.
/// * Merkle authentication paths for all queries.
struct TraceQueries {
    query_proofs: Vec<SaltedBatchMerkleProof<Rpo256>>,
    main_states: Table<Felt>,
}

impl TraceQueries {
    /// Parses the provided trace queries into trace states in the specified field and
    /// corresponding Merkle authentication paths.
    pub fn new(
        mut queries: Vec<Queries>,
        air: &RescueAir,
        num_queries: usize,
    ) -> Result<Self, VerifierError> {
        // parse main trace segment queries; parsing also validates that hashes of each table row
        // form the leaves of Merkle authentication paths in the proofs
        let main_segment_width = air.trace_info().main_trace_width();
        let main_segment_queries = queries.remove(0);
        let (main_segment_query_proofs, main_segment_states) = main_segment_queries
            .parse::<Felt, Rpo256, SaltedMerkleTree<Rpo256, ChaCha20Rng>>(
                air.lde_domain_size(),
                num_queries,
                main_segment_width,
            )
            .map_err(|err| {
                VerifierError::ProofDeserializationError(format!(
                    "main trace segment query deserialization failed: {err}"
                ))
            })?;

        // all query proofs will be aggregated into a single vector
        let query_proofs = vec![main_segment_query_proofs];

        Ok(Self {
            query_proofs,
            main_states: main_segment_states,
        })
    }
}

// CONSTRAINT QUERIES
// ================================================================================================

/// Container of constraint evaluation query data, including:
/// * Queried constraint evaluation values.
/// * Merkle authentication paths for all queries.
struct ConstraintQueries {
    query_proofs: SaltedBatchMerkleProof<Rpo256>,
    evaluations: Table<QuadExt>,
}

impl ConstraintQueries {
    /// Parses the provided constraint queries into evaluations in the specified field and
    /// corresponding Merkle authentication paths.
    pub fn new(
        queries: Queries,
        air: &RescueAir,
        num_queries: usize,
    ) -> Result<Self, VerifierError> {
        let constraint_frame_width = air.context().num_constraint_composition_columns() + 1;

        let (query_proofs, evaluations) = queries
            .parse::<QuadExt, Rpo256, SaltedMerkleTree<Rpo256, ChaCha20Rng>>(
                air.lde_domain_size(),
                num_queries,
                constraint_frame_width,
            )
            .map_err(|err| {
                VerifierError::ProofDeserializationError(format!(
                    "constraint evaluation query deserialization failed: {err}"
                ))
            })?;

        Ok(Self { query_proofs, evaluations })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Takes a set of positions, query values of a trace at these positions and a Merkle batch proof
/// against a committment to this trace, and outputs a partial Merkle tree with individual Merkle
/// paths for each position as well as a key-value map mapping the digests of the query values
/// (i.e. Merkle tree leaves) to their corresponding query values.
pub fn unbatch_to_partial_mt(
    positions: Vec<usize>,
    queries: Vec<Vec<Felt>>,
    proof: SaltedBatchMerkleProof<Rpo256>,
) -> (PartialMerkleTree, Vec<(Digest, Vec<Felt>)>) {
    // hash the query values with the salts in order to get the leaf
    let (salts, proof) = proof;
    let leaves: Vec<Digest> = queries
        .iter()
        .zip(salts.iter())
        .map(|(row, salt)| {
            let leaf = Rpo256::hash_elements(row);
            Rpo256::merge(&[leaf, *salt])
        })
        .collect();
    // use the computed leaves with the indices in order to unbatch the Merkle proof batch proof
    let unbatched_proof = proof
        .into_openings(&leaves, &positions)
        .expect("failed to unbatch the batched Merkle proof");

    // construct the partial Merkle tree data
    let mut paths_with_leaves = vec![];
    for (position, merkle_proof) in positions.iter().zip(unbatched_proof.iter()) {
        paths_with_leaves.push((
            *position as u64,
            merkle_proof.0.to_owned(),
            merkle_proof.1.to_owned().into(),
        ))
    }

    // construct the advice key map linking leaves to query values
    let mut adv_key_map = Vec::new();
    leaves.into_iter().zip(queries.iter().zip(salts.iter())).for_each(
        |(leaf, (query_data, salt))| {
            adv_key_map.push((
                leaf,
                query_data.iter().copied().chain(salt.as_elements().iter().copied()).collect(),
            ));
        },
    );

    (
        PartialMerkleTree::with_paths(paths_with_leaves).expect("should not fail from paths"),
        adv_key_map,
    )
}
