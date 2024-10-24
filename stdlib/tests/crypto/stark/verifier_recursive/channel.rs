// VERIFIER CHANNEL
// ================================================================================================

use alloc::vec::Vec;

use miden_air::ProcessorAir;
use test_utils::{
    crypto::{BatchMerkleProof, MerklePath, PartialMerkleTree, Rpo256, RpoDigest},
    group_slice_elements,
    math::{FieldElement, QuadExtension, StarkField},
    Felt, VerifierError, EMPTY_WORD,
};
use winter_air::{
    proof::{Proof, Queries, Table, TraceOodFrame},
    Air,
};
use winter_crypto::MerkleTree as MerkleTreeVC;
use winter_fri::{folding::fold_positions, VerifierChannel as FriVerifierChannel};

pub type QuadExt = QuadExtension<Felt>;

type AdvMap = Vec<(RpoDigest, Vec<Felt>)>;

/// A view into a [Proof] for a computation structured to simulate an "interactive" channel.
///
/// A channel is instantiated for a specific proof, which is parsed into structs over the
/// appropriate field (specified by type parameter `E`). This also validates that the proof is
/// well-formed in the context of the computation for the specified [Air].
pub struct VerifierChannel {
    // trace queries
    trace_roots: Vec<RpoDigest>,
    trace_queries: Option<TraceQueries>,
    // constraint queries
    constraint_root: RpoDigest,
    constraint_queries: Option<ConstraintQueries>,
    // FRI proof
    fri_roots: Option<Vec<RpoDigest>>,
    fri_layer_proofs: Vec<BatchMerkleProof<Rpo256>>,
    fri_layer_queries: Vec<Vec<QuadExt>>,
    fri_remainder: Option<Vec<QuadExt>>,
    fri_num_partitions: usize,
    // out-of-domain frame
    ood_trace_frame: Option<TraceOodFrame<QuadExt>>,
    ood_constraint_evaluations: Option<Vec<QuadExt>>,
    // query proof-of-work
    pow_nonce: u64,
}

impl VerifierChannel {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates and returns a new [VerifierChannel] initialized from the specified `proof`.
    pub fn new(air: &ProcessorAir, proof: Proof) -> Result<Self, VerifierError> {
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
        } = proof;

        // make AIR and proof base fields are the same
        if Felt::get_modulus_le_bytes() != context.field_modulus_bytes() {
            return Err(VerifierError::InconsistentBaseField);
        }

        let num_trace_segments = air.trace_info().num_segments();
        let main_trace_width = air.trace_info().main_segment_width();
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
        let (fri_layer_queries, fri_layer_proofs) = fri_proof
            .parse_layers::<QuadExt, Rpo256, MerkleTreeVC<Rpo256>>(
                lde_domain_size,
                fri_options.folding_factor(),
            )
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        // --- parse out-of-domain evaluation frame -----------------------------------------------
        let (ood_trace_evaluations, ood_constraint_evaluations) = ood_frame
            .parse(main_trace_width, aux_trace_width, constraint_frame_width)
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
            // out-of-domain evaluation
            ood_trace_frame: Some(ood_trace_evaluations),
            ood_constraint_evaluations: Some(ood_constraint_evaluations),
            // query seed
            pow_nonce,
        })
    }

    // DATA READERS
    // --------------------------------------------------------------------------------------------

    /// Returns execution trace commitments sent by the prover.
    ///
    /// For computations requiring multiple trace segment, the returned slice will contain a
    /// commitment for each trace segment.
    pub fn read_trace_commitments(&self) -> &[RpoDigest] {
        &self.trace_roots
    }

    /// Returns constraint evaluation commitment sent by the prover.
    pub fn read_constraint_commitment(&self) -> RpoDigest {
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

    /// Returns trace states at the specified positions of the LDE domain. This also checks if
    /// the trace states are valid against the trace commitment sent by the prover.
    ///
    /// For computations requiring multiple trace segments, trace states for auxiliary segments
    /// are also included as the second value of the returned tuple (trace states for all auxiliary
    /// segments are merged into a single table). Otherwise, the second value is None.
    #[allow(clippy::type_complexity)]
    pub fn read_queried_trace_states(
        &mut self,
        positions: &[usize],
    ) -> Result<(AdvMap, Vec<PartialMerkleTree>), VerifierError> {
        let queries = self.trace_queries.take().expect("already read");
        let mut trees = Vec::new();

        let proofs: Vec<_> = queries.query_proofs.into_iter().collect();
        let main_queries = queries.main_states.clone();
        let aux_queries = queries.aux_states.clone();
        let main_queries_vec: Vec<Vec<Felt>> = main_queries.rows().map(|a| a.to_owned()).collect();
        let aux_queries_vec: Vec<Vec<Felt>> = aux_queries
            .as_ref()
            .unwrap()
            .rows()
            .map(|a| QuadExt::slice_as_base_elements(a).to_vec())
            .collect();
        let (main_trace_pmt, mut main_trace_adv_map) =
            unbatch_to_partial_mt(positions.to_vec(), main_queries_vec, proofs[0].clone());
        let (aux_trace_pmt, mut aux_trace_adv_map) =
            unbatch_to_partial_mt(positions.to_vec(), aux_queries_vec, proofs[1].clone());
        trees.push(main_trace_pmt);
        trees.push(aux_trace_pmt);
        main_trace_adv_map.append(&mut aux_trace_adv_map);
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

        let queries_: Vec<Vec<Felt>> = queries
            .evaluations
            .rows()
            .map(|a| a.iter().flat_map(|x| QuadExt::to_base_elements(*x).to_owned()).collect())
            .collect();
        let (constraint_pmt, constraint_adv_map) =
            unbatch_to_partial_mt(positions.to_vec(), queries_, proof);

        Ok((constraint_adv_map, constraint_pmt))
    }

    // Get the FRI layer challenges alpha
    pub fn fri_layer_commitments(&self) -> Option<Vec<RpoDigest>> {
        self.fri_roots.clone()
    }

    // Get remainder codeword
    pub fn fri_remainder(&self) -> Vec<QuadExt> {
        self.fri_remainder.clone().unwrap()
    }
    //
    pub fn layer_proofs(&self) -> Vec<BatchMerkleProof<Rpo256>> {
        self.fri_layer_proofs.clone()
    }

    pub fn unbatch<const N: usize, const W: usize>(
        &mut self,
        positions_: &[usize],
        domain_size: usize,
        layer_commitments: Vec<RpoDigest>,
    ) -> (Vec<PartialMerkleTree>, Vec<(RpoDigest, Vec<Felt>)>) {
        let queries = self.fri_layer_queries.clone();
        let mut current_domain_size = domain_size;
        let mut positions = positions_.to_vec();
        let depth = layer_commitments.len() - 1;

        let mut adv_key_map = Vec::new();
        let mut partial_trees = Vec::new();
        let mut layer_proofs = self.layer_proofs();
        for query in queries.iter().take(depth) {
            let mut folded_positions = fold_positions(&positions, current_domain_size, N);

            let layer_proof = layer_proofs.remove(0);

            let x = group_slice_elements::<QuadExt, N>(query);
            let leaves: Vec<RpoDigest> = x.iter().map(|row| Rpo256::hash_elements(row)).collect();
            let unbatched_proof = layer_proof.into_openings(&leaves, &folded_positions).unwrap();

            let nodes: Vec<[Felt; 4]> =
                leaves.iter().map(|leaf| [leaf[0], leaf[1], leaf[2], leaf[3]]).collect();

            let paths: Vec<MerklePath> =
                unbatched_proof.into_iter().map(|list| list.1.into()).collect();

            let iter_pos = folded_positions.iter_mut().map(|a| *a as u64);
            let nodes_tmp = nodes.clone();
            let iter_nodes = nodes_tmp.iter();
            let iter_paths = paths.into_iter();
            let mut tmp_vec = Vec::new();
            for (p, (node, path)) in iter_pos.zip(iter_nodes.zip(iter_paths)) {
                tmp_vec.push((p, RpoDigest::from(*node), path));
            }

            let new_pmt =
                PartialMerkleTree::with_paths(tmp_vec).expect("should not fail from paths");
            partial_trees.push(new_pmt);

            nodes.into_iter().zip(x.iter()).for_each(|(a, b)| {
                let mut value = QuadExt::slice_as_base_elements(b).to_owned();
                value.extend(EMPTY_WORD);

                adv_key_map.push((a.to_owned().into(), value));
            });

            core::mem::swap(&mut positions, &mut folded_positions);
            current_domain_size /= N;
        }

        (partial_trees, adv_key_map)
    }
}

// FRI VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

impl FriVerifierChannel<QuadExt> for VerifierChannel {
    type Hasher = Rpo256;
    type VectorCommitment = MerkleTreeVC<Self::Hasher>;

    fn read_fri_num_partitions(&self) -> usize {
        self.fri_num_partitions
    }

    fn read_fri_layer_commitments(&mut self) -> Vec<RpoDigest> {
        self.fri_roots.take().expect("already read")
    }

    fn take_next_fri_layer_proof(&mut self) -> BatchMerkleProof<Rpo256> {
        self.fri_layer_proofs.remove(0)
    }

    fn take_next_fri_layer_queries(&mut self) -> Vec<QuadExt> {
        self.fri_layer_queries.remove(0)
    }

    fn take_fri_remainder(&mut self) -> Vec<QuadExt> {
        self.fri_remainder.take().expect("already read")
    }
}

// TRACE QUERIES
// ================================================================================================

/// Container of trace query data, including:
/// * Queried states for all trace segments.
/// * Merkle authentication paths for all queries.
///
/// Trace states for all auxiliary segments are stored in a single table.
struct TraceQueries {
    query_proofs: Vec<BatchMerkleProof<Rpo256>>,
    main_states: Table<Felt>,
    aux_states: Option<Table<QuadExt>>,
}

impl TraceQueries {
    /// Parses the provided trace queries into trace states in the specified field and
    /// corresponding Merkle authentication paths.
    pub fn new(
        mut queries: Vec<Queries>,
        air: &ProcessorAir,
        num_queries: usize,
    ) -> Result<Self, VerifierError> {
        // parse main trace segment queries; parsing also validates that hashes of each table row
        // form the leaves of Merkle authentication paths in the proofs
        let main_segment_width = air.trace_info().main_segment_width();
        let main_segment_queries = queries.remove(0);
        let (main_segment_query_proofs, main_segment_states) = main_segment_queries
            .parse::<Felt, Rpo256, MerkleTreeVC<Rpo256>>(
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
        let mut query_proofs = vec![main_segment_query_proofs];

        // parse auxiliary trace segment queries (if any); parsing also validates that hashes of
        // each table row form the leaves of Merkle authentication paths in the proofs
        let aux_trace_states = if air.trace_info().is_multi_segment() {
            assert_eq!(queries.len(), 1);
            let segment_width = air.trace_info().aux_segment_width();
            let aux_segment_queries = queries.remove(0);

            let (segment_query_proof, segment_trace_states) = aux_segment_queries
                .parse::<QuadExt, Rpo256, MerkleTreeVC<Rpo256>>(
                    air.lde_domain_size(),
                    num_queries,
                    segment_width,
                )
                .map_err(|err| {
                    VerifierError::ProofDeserializationError(format!(
                        "auxiliary trace segment query deserialization failed: {err}"
                    ))
                })?;

            query_proofs.push(segment_query_proof);

            Some(segment_trace_states)
        } else {
            None
        };

        Ok(Self {
            query_proofs,
            main_states: main_segment_states,
            aux_states: aux_trace_states,
        })
    }
}

// CONSTRAINT QUERIES
// ================================================================================================

/// Container of constraint evaluation query data, including:
/// * Queried constraint evaluation values.
/// * Merkle authentication paths for all queries.
struct ConstraintQueries {
    query_proofs: BatchMerkleProof<Rpo256>,
    evaluations: Table<QuadExt>,
}

impl ConstraintQueries {
    /// Parses the provided constraint queries into evaluations in the specified field and
    /// corresponding Merkle authentication paths.
    pub fn new(
        queries: Queries,
        air: &ProcessorAir,
        num_queries: usize,
    ) -> Result<Self, VerifierError> {
        let (query_proofs, evaluations) = queries
            .parse::<QuadExt, Rpo256, MerkleTreeVC<Rpo256>>(
                air.lde_domain_size(),
                num_queries,
                air.ce_blowup_factor(),
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

pub fn unbatch_to_partial_mt(
    mut positions: Vec<usize>,
    queries: Vec<Vec<Felt>>,
    proof: BatchMerkleProof<Rpo256>,
) -> (PartialMerkleTree, Vec<(RpoDigest, Vec<Felt>)>) {
    let leaves: Vec<RpoDigest> = queries.iter().map(|row| Rpo256::hash_elements(row)).collect();

    let unbatched_proof = proof.into_openings(&leaves, &positions).unwrap();
    let mut adv_key_map = Vec::new();
    let nodes: Vec<[Felt; 4]> =
        queries.iter().map(|node| [node[0], node[1], node[2], node[3]]).collect();

    let paths: Vec<MerklePath> = unbatched_proof.into_iter().map(|list| list.1.into()).collect();

    let iter_pos = positions.iter_mut().map(|a| *a as u64);
    let nodes_tmp = nodes.clone();
    let iter_nodes = nodes_tmp.iter();
    let iter_paths = paths.into_iter();
    let mut tmp_vec = vec![];
    for (p, (node, path)) in iter_pos.zip(iter_nodes.zip(iter_paths)) {
        tmp_vec.push((p, RpoDigest::from(*node), path));
    }

    nodes.into_iter().zip(queries.iter()).for_each(|(a, b)| {
        let data = b.to_owned();
        adv_key_map.push((a.to_owned().into(), data));
    });

    (
        PartialMerkleTree::with_paths(tmp_vec).expect("should not fail from paths"),
        adv_key_map,
    )
}
