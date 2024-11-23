//! This module contains GPU acceleration logic for Browser
//! For now, the logic is limited to GPU accelerating trace and constraint commitments,
//! using the RPO 256 or RPX 256 hash functions.

#[cfg(not(feature = "std"))]
use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::{boxed::Box, marker::PhantomData, time::Instant, vec::Vec};

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use air::{AuxRandElements, LagrangeKernelEvaluationFrame, PartitionOptions};
use elsa::FrozenVec;
use miden_gpu::{
    webgpu::{get_or_init_webgpu, RowHasher},
    HashFn,
};
use processor::{
    crypto::{ElementHasher, Hasher},
    ONE,
};
use tracing::info_span;
#[cfg(feature = "std")]
use tracing::{event, Level};
use winter_maybe_async::{maybe_async, maybe_await};
use winter_prover::crypto::VectorCommitment;
use winter_prover::{
    crypto::{Digest, MerkleTree},
    matrix::{get_evaluation_offsets, ColMatrix, RowMatrix, Segment},
    proof::Queries,
    CompositionPoly, CompositionPolyTrace, ConstraintCommitment, ConstraintCompositionCoefficients,
    DefaultConstraintEvaluator, EvaluationFrame, Prover, StarkDomain, TraceInfo, TraceLde,
    TracePolyTable,
};

use crate::{
    crypto::{RandomCoin, Rpo256},
    math::fft,
    ExecutionProver, ExecutionTrace, Felt, FieldElement, ProcessorAir, PublicInputs,
    WinterProofOptions,
};

#[cfg(test)]
mod tests;

#[allow(clippy::uninit_vec)]
pub unsafe fn uninit_vector_real<T>(length: usize) -> Vec<T> {
    let mut vector = Vec::with_capacity(length);
    vector.set_len(length);
    vector
}

// CONSTANTS
// ================================================================================================

// The Rate for RPO and RPX is the same
const RATE: usize = Rpo256::RATE_RANGE.end - Rpo256::RATE_RANGE.start;
const DIGEST_SIZE: usize = Rpo256::DIGEST_RANGE.end - Rpo256::DIGEST_RANGE.start;

// WebGPU RPO/RPX PROVER
// ================================================================================================

/// Wraps an [ExecutionProver] and provides GPU acceleration for building trace commitments.
pub(crate) struct WebGPUExecutionProver<H, D, R>
where
    H: Hasher<Digest = D> + ElementHasher<BaseField = R::BaseField>,
    D: Digest + for<'a> From<&'a [Felt; DIGEST_SIZE]>,
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
{
    pub execution_prover: ExecutionProver<H, R>,
    pub webgpu_hash_fn: HashFn,
    phantom_data: PhantomData<D>,
}

impl<H, D, R> WebGPUExecutionProver<H, D, R>
where
    H: Hasher<Digest = D> + ElementHasher<BaseField = R::BaseField> + Sync,
    D: Digest + for<'a> From<&'a [Felt; DIGEST_SIZE]>,
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
{
    pub fn new(execution_prover: ExecutionProver<H, R>, hash_fn: HashFn) -> Self {
        WebGPUExecutionProver {
            execution_prover,
            webgpu_hash_fn: hash_fn,
            phantom_data: PhantomData,
        }
    }

    fn build_aligned_segment<E, const N: usize>(
        polys: &ColMatrix<E>,
        poly_offset: usize,
        offsets: &[Felt],
        twiddles: &[Felt],
    ) -> Segment<Felt, N>
    where
        E: FieldElement<BaseField = Felt>,
    {
        let poly_size = polys.num_rows();
        let domain_size = offsets.len();
        assert!(domain_size.is_power_of_two());
        assert!(domain_size > poly_size);
        assert_eq!(poly_size, twiddles.len() * 2);
        assert!(poly_offset < polys.num_base_cols());

        // allocate memory for the segment
        let data = if polys.num_base_cols() - poly_offset >= N {
            // if we will fill the entire segment, we allocate uninitialized memory
            unsafe { uninit_vector_real(domain_size) }
        } else {
            // but if some columns in the segment will remain unfilled, we allocate memory
            // initialized to zeros to make sure we don't end up with memory with
            // undefined values
            vec![[E::BaseField::ZERO; N]; domain_size]
        };

        Segment::new_with_buffer(data, polys, poly_offset, offsets, twiddles)
    }

    fn build_aligned_segments<E, const N: usize>(
        polys: &ColMatrix<E>,
        twiddles: &[Felt],
        offsets: &[Felt],
    ) -> Vec<Segment<Felt, N>>
    where
        E: FieldElement<BaseField = Felt>,
    {
        assert!(N > 0, "batch size N must be greater than zero");
        debug_assert_eq!(polys.num_rows(), twiddles.len() * 2);
        debug_assert_eq!(offsets.len() % polys.num_rows(), 0);

        let num_segments = if polys.num_base_cols() % N == 0 {
            polys.num_base_cols() / N
        } else {
            polys.num_base_cols() / N + 1
        };

        (0..num_segments)
            .map(|i| Self::build_aligned_segment(polys, i * N, offsets, twiddles))
            .collect()
    }
}

#[maybe_async]
impl<H, D, R> Prover for WebGPUExecutionProver<H, D, R>
where
    H: Hasher<Digest = D> + ElementHasher<BaseField = R::BaseField> + Sync,
    D: Digest + for<'a> From<&'a [Felt; DIGEST_SIZE]>,
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
{
    type BaseField = Felt;
    type Air = ProcessorAir;
    type Trace = ExecutionTrace;
    type VC = MerkleTree<Self::HashFn>;
    type HashFn = H;
    type RandomCoin = R;
    type TraceLde<E: FieldElement<BaseField = Felt>> = WebGPUTraceLde<E, H>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, ProcessorAir, E>;

    fn get_pub_inputs(&self, trace: &ExecutionTrace) -> PublicInputs {
        self.execution_prover.get_pub_inputs(trace)
    }

    fn options(&self) -> &WinterProofOptions {
        self.execution_prover.options()
    }

    #[maybe_async]
    fn new_trace_lde<E: FieldElement<BaseField = Felt>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Felt>,
        domain: &StarkDomain<Felt>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        maybe_await!(WebGPUTraceLde::new(
            trace_info,
            main_trace,
            domain,
            self.webgpu_hash_fn,
            partition_option
        ))
    }

    #[maybe_async]
    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a ProcessorAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        maybe_await!(self.execution_prover.new_evaluator(
            air,
            aux_rand_elements,
            composition_coefficients
        ))
    }

    /// Evaluates constraint composition polynomial over the LDE domain and builds a commitment
    /// to these evaluations.
    ///
    /// The evaluation is done by evaluating each composition polynomial column over the LDE
    /// domain.
    ///
    /// The commitment is computed by hashing each row in the evaluation matrix, and then building
    /// a Merkle tree from the resulting hashes.
    ///
    /// The composition polynomial columns are evaluated on the CPU. Afterwards the commitment
    /// is computed on the GPU.
    ///
    /// ```text
    ///        ─────────────────────────────────────────────────────
    ///              ┌───┐ ┌───┐
    ///  CPU:   ... ─┤fft├─┤fft├─┐                           ┌─ ...
    ///              └───┘ └───┘ │                           │
    ///        ╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴┼╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴┼╴╴╴╴╴╴
    ///                          │ ┌──────────┐ ┌──────────┐ │
    ///  GPU:                    └─┤   hash   ├─┤   hash   ├─┘
    ///                            └──────────┘ └──────────┘
    ///        ────┼────────┼────────┼────────┼────────┼────────┼───
    ///           t=n     t=n+1    t=n+2     t=n+3   t=n+4    t=n+5
    /// ```
    #[maybe_async]
    fn build_constraint_commitment<E: FieldElement<BaseField = Felt>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_trace_poly_columns: usize,
        domain: &StarkDomain<Felt>,
    ) -> (
        ConstraintCommitment<E, Self::HashFn, MerkleTree<Self::HashFn>>,
        CompositionPoly<E>,
    ) {
        // evaluate composition polynomial columns over the LDE domain
        #[cfg(feature = "std")]
        let now = Instant::now();
        let composition_poly =
            CompositionPoly::new(composition_poly_trace, domain, num_trace_poly_columns);
        let blowup = domain.trace_to_lde_blowup();
        let offsets =
            get_evaluation_offsets::<E>(composition_poly.column_len(), blowup, domain.offset());
        let segments = Self::build_aligned_segments(
            composition_poly.data(),
            domain.trace_twiddles(),
            &offsets,
        );
        #[cfg(feature = "std")]
        event!(
            Level::INFO,
            "Evaluated {} composition polynomial columns over LDE domain (2^{} elements) in {} ms",
            composition_poly.num_columns(),
            offsets.len().ilog2(),
            now.elapsed().as_millis()
        );
        let helper = maybe_await!(get_or_init_webgpu());

        // build constraint evaluation commitment
        #[cfg(feature = "std")]
        let now = Instant::now();
        let lde_domain_size = domain.lde_domain_size();
        let num_base_columns =
            composition_poly.num_columns() * <E as FieldElement>::EXTENSION_DEGREE;
        let mut row_hasher =
            RowHasher::<H>::new(helper, lde_domain_size, num_base_columns, self.webgpu_hash_fn);
        for segment in segments.iter() {
            row_hasher.update(segment);
        }
        let row_hashes = maybe_await!(row_hasher.finish());
        let tree_nodes =
            maybe_await!(helper.build_merkle_tree::<H>(&row_hashes, self.webgpu_hash_fn));
        // aggregate segments at the same time as the GPU generates the merkle tree nodes
        let composed_evaluations = RowMatrix::<E>::from_segments(segments, num_base_columns);
        let commitment = MerkleTree::<H>::from_raw_parts(tree_nodes, row_hashes).unwrap();
        let constraint_commitment = ConstraintCommitment::new(composed_evaluations, commitment);
        #[cfg(feature = "std")]
        event!(
            Level::INFO,
            "Computed constraint evaluation commitment on the GPU (Merkle tree of depth {}) in {} ms",
            lde_domain_size.ilog2(),
            now.elapsed().as_millis()
        );
        (constraint_commitment, composition_poly)
    }
}

// TRACE LOW DEGREE EXTENSION (WebGPU)
// ================================================================================================

/// Contains all segments of the extended execution trace, the commitments to these segments, the
/// LDE blowup factor, and the [TraceInfo].
///
/// Segments are stored in two groups:
/// - Main segment: this is the first trace segment generated by the prover. Values in this segment
///   will always be elements in the base field (even when an extension field is used).
/// - Auxiliary segments: a list of 0 or more segments for traces generated after the prover commits
///   to the first trace segment. Currently, at most 1 auxiliary segment is possible.
pub struct WebGPUTraceLde<E: FieldElement<BaseField = Felt>, H: Hasher> {
    // low-degree extension of the main segment of the trace
    main_segment_lde: RowMatrix<Felt>,
    // commitment to the main segment of the trace
    main_segment_tree: MerkleTree<H>,
    // low-degree extensions of the auxiliary segments of the trace
    aux_segment_lde: Option<RowMatrix<E>>,
    // commitment to the auxiliary segments of the trace
    aux_segment_tree: Option<MerkleTree<H>>,
    blowup: usize,
    trace_info: TraceInfo,
    webgpu_hash_fn: HashFn,
    partition_option: PartitionOptions,
}

impl<
        E: FieldElement<BaseField = Felt>,
        H: Hasher<Digest = D> + ElementHasher<BaseField = E::BaseField>,
        D: Digest + for<'a> From<&'a [Felt; DIGEST_SIZE]>,
    > WebGPUTraceLde<E, H>
{
    /// Takes the main trace segment columns as input, interpolates them into polynomials in
    /// coefficient form, evaluates the polynomials over the LDE domain, commits to the
    /// polynomial evaluations, and creates a new [DefaultTraceLde] with the LDE of the main trace
    /// segment and the commitment.
    ///
    /// Returns a tuple containing a [TracePolyTable] with the trace polynomials for the main trace
    /// segment and the new [DefaultTraceLde].
    pub async fn new(
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Felt>,
        domain: &StarkDomain<Felt>,
        webgpu_hash_fn: HashFn,
        partition_option: PartitionOptions,
    ) -> (Self, TracePolyTable<E>) {
        // extend the main execution trace and build a Merkle tree from the extended trace
        let (main_segment_lde, main_segment_tree, main_segment_polys) =
            build_trace_commitment(main_trace, domain, webgpu_hash_fn).await;

        let trace_poly_table = TracePolyTable::new(main_segment_polys);
        let trace_lde = WebGPUTraceLde {
            main_segment_lde,
            main_segment_tree,
            aux_segment_lde: None,
            aux_segment_tree: None,
            blowup: domain.trace_to_lde_blowup(),
            trace_info: trace_info.clone(),
            webgpu_hash_fn,
            partition_option,
        };

        (trace_lde, trace_poly_table)
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns number of columns in the main segment of the execution trace.
    #[allow(unused)]
    #[cfg(test)]
    pub fn main_segment_width(&self) -> usize {
        self.main_segment_lde.num_cols()
    }

    /// Returns a reference to [Matrix] representing the main trace segment.
    #[allow(unused)]
    #[cfg(test)]
    pub fn get_main_segment(&self) -> &RowMatrix<Felt> {
        &self.main_segment_lde
    }

    /// Returns the entire trace for the column at the specified index.
    #[allow(unused)]
    #[cfg(test)]
    pub fn get_main_segment_column(&self, col_idx: usize) -> Vec<Felt> {
        (0..self.main_segment_lde.num_rows())
            .map(|row_idx| self.main_segment_lde.get(col_idx, row_idx))
            .collect()
    }
}

#[maybe_async]
impl<
        E: FieldElement<BaseField = Felt>,
        H: Hasher<Digest = D> + ElementHasher<BaseField = E::BaseField>,
        D: Digest + for<'a> From<&'a [Felt; DIGEST_SIZE]>,
    > TraceLde<E> for WebGPUTraceLde<E, H>
{
    type HashFn = H;
    type VC = MerkleTree<Self::HashFn>;

    /// Returns the commitment to the low-degree extension of the main trace segment.
    fn get_main_trace_commitment(&self) -> D {
        let root_hash = self.main_segment_tree.root();
        *root_hash
    }

    /// Takes auxiliary trace segment columns as input, interpolates them into polynomials in
    /// coefficient form, evaluates the polynomials over the LDE domain, and commits to the
    /// polynomial evaluations.
    ///
    /// Returns a tuple containing the column polynomials in coefficient from and the commitment
    /// to the polynomial evaluations over the LDE domain.
    ///
    /// # Panics
    ///
    /// This function will panic if any of the following are true:
    /// - the number of rows in the provided `aux_trace` does not match the main trace.
    /// - this segment would exceed the number of segments specified by the trace layout.
    fn set_aux_trace(
        &mut self,
        aux_trace: &ColMatrix<E>,
        domain: &StarkDomain<Felt>,
    ) -> (ColMatrix<E>, D) {
        // extend the auxiliary trace segment and build a Merkle tree from the extended trace
        let (aux_segment_lde, aux_segment_tree, aux_segment_polys) =
            build_trace_commitment_sync::<E, E, H, Self::VC>(
                aux_trace,
                domain,
                self.partition_option.partition_size::<E>(aux_trace.num_cols()),
            );

        assert_eq!(
            self.main_segment_lde.num_rows(),
            aux_segment_lde.num_rows(),
            "the number of rows in the auxiliary segment must be the same as in the main segment"
        );

        // save the lde and commitment
        self.aux_segment_lde = Some(aux_segment_lde);
        let root_hash = *aux_segment_tree.root();
        self.aux_segment_tree = Some(aux_segment_tree);

        (aux_segment_polys, root_hash)
    }

    /// Reads current and next rows from the main trace segment into the specified frame.
    fn read_main_trace_frame_into(&self, lde_step: usize, frame: &mut EvaluationFrame<Felt>) {
        // at the end of the trace, next state wraps around and we read the first step again
        let next_lde_step = (lde_step + self.blowup()) % self.trace_len();

        // copy main trace segment values into the frame
        frame.current_mut().copy_from_slice(self.main_segment_lde.row(lde_step));
        frame.next_mut().copy_from_slice(self.main_segment_lde.row(next_lde_step));
    }

    /// Reads current and next rows from the auxiliary trace segment into the specified frame.
    ///
    /// # Panics
    /// This currently assumes that there is exactly one auxiliary trace segment, and will panic
    /// otherwise.
    fn read_aux_trace_frame_into(&self, lde_step: usize, frame: &mut EvaluationFrame<E>) {
        // at the end of the trace, next state wraps around and we read the first step again
        let next_lde_step = (lde_step + self.blowup()) % self.trace_len();

        // copy auxiliary trace segment values into the frame
        if let Some(mat) = self.aux_segment_lde.as_ref() {
            frame.current_mut().copy_from_slice(mat.row(lde_step));
            frame.next_mut().copy_from_slice(mat.row(next_lde_step));
        }
    }

    /// Returns trace table rows at the specified positions along with Merkle authentication paths
    /// from the commitment root to these rows.
    fn query(&self, positions: &[usize]) -> Vec<Queries> {
        // build queries for the main trace segment
        let mut result = vec![build_segment_queries(
            &self.main_segment_lde,
            &self.main_segment_tree,
            positions,
        )];

        if let (Some(aux_segment_lde), Some(aux_segment_tree)) =
            (&self.aux_segment_lde, &self.aux_segment_tree)
        {
            result.push(build_segment_queries(aux_segment_lde, aux_segment_tree, positions));
        }

        result
    }

    /// Returns the number of rows in the execution trace.
    fn trace_len(&self) -> usize {
        self.main_segment_lde.num_rows()
    }

    /// Returns blowup factor which was used to extend the original execution trace into trace LDE.
    fn blowup(&self) -> usize {
        self.blowup
    }

    /// Populates the provided Lagrange kernel frame starting at the current row (as defined by
    /// lde_step).
    /// Note that unlike EvaluationFrame, the Lagrange kernel frame includes only the Lagrange
    /// kernel column (as opposed to all columns).
    fn read_lagrange_kernel_frame_into(
        &self,
        lde_step: usize,
        col_idx: usize,
        frame: &mut LagrangeKernelEvaluationFrame<E>,
    ) {
        if let Some(aux_segment) = self.aux_segment_lde.as_ref() {
            let frame = frame.frame_mut();
            frame.truncate(0);

            frame.push(aux_segment.get(col_idx, lde_step));

            let frame_length = self.trace_info.length().ilog2() as usize + 1;
            for i in 0..frame_length - 1 {
                let shift = self.blowup() * (1 << i);
                let next_lde_step = (lde_step + shift) % self.trace_len();

                frame.push(aux_segment.get(col_idx, next_lde_step));
            }
        }
    }

    /// Returns the trace info
    fn trace_info(&self) -> &TraceInfo {
        &self.trace_info
    }
}

/// Computes a low-degree extension (LDE) of the provided execution trace over the specified
/// domain and builds a commitment to the extended trace.
///
/// The extension is performed by interpolating each column of the execution trace into a
/// polynomial of degree = trace_length - 1, and then evaluating the polynomial over the LDE
/// domain.
///
/// Trace commitment is computed by hashing each row of the extended execution trace, and then
/// building a Merkle tree from the resulting hashes.
///
/// Interpolations and evaluations are computed on the CPU while hashes are simultaneously
/// computed on the GPU:
///
/// ```text
///        ──────────────────────────────────────────────────────
///               ┌───┐   ┌────┐   ┌───┐   ┌────┐   ┌───┐
///  CPU:   ... ──┤fft├─┬─┤ifft├───┤fft├─┬─┤ifft├───┤fft├─┬─ ...
///               └───┘ │ └────┘   └───┘ │ └────┘   └───┘ │
///        ╴╴╴╴╴╴╴╴╴╴╴╴╴┼╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴┼╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴┼╴╴╴╴╴╴
///                     │ ┌──────────┐   │ ┌──────────┐   │
///  GPU:               └─┤   hash   │   └─┤   hash   │   └─ ...
///                       └──────────┘     └──────────┘
///        ────┼────────┼────────┼────────┼────────┼────────┼────
///           t=n     t=n+1    t=n+2     t=n+3   t=n+4    t=n+5
/// ```
const DEFAULT_SEGMENT_WIDTH: usize = 8;

fn build_trace_commitment_sync<E, F, H, V>(
    trace: &ColMatrix<F>,
    domain: &StarkDomain<E::BaseField>,
    partition_size: usize,
) -> (RowMatrix<F>, V, ColMatrix<F>)
where
    E: FieldElement,
    F: FieldElement<BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
{
    // extend the execution trace
    let (trace_lde, trace_polys) = {
        let span = info_span!(
            "extend_execution_trace",
            num_cols = trace.num_cols(),
            blowup = domain.trace_to_lde_blowup()
        )
        .entered();
        let trace_polys = trace.interpolate_columns();
        let trace_lde =
            RowMatrix::evaluate_polys_over::<DEFAULT_SEGMENT_WIDTH>(&trace_polys, domain);
        drop(span);

        (trace_lde, trace_polys)
    };
    assert_eq!(trace_lde.num_cols(), trace.num_cols());
    assert_eq!(trace_polys.num_rows(), trace.num_rows());
    assert_eq!(trace_lde.num_rows(), domain.lde_domain_size());

    // build trace commitment
    let commitment_domain_size = trace_lde.num_rows();
    let trace_vector_com = info_span!("compute_execution_trace_commitment", commitment_domain_size)
        .in_scope(|| trace_lde.commit_to_rows::<H, V>(partition_size));
    assert_eq!(trace_vector_com.domain_len(), commitment_domain_size);

    (trace_lde, trace_vector_com, trace_polys)
}

async fn build_trace_commitment<
    E: FieldElement<BaseField = Felt>,
    H: Hasher<Digest = D> + ElementHasher<BaseField = E::BaseField>,
    D: Digest + for<'a> From<&'a [Felt; DIGEST_SIZE]>,
>(
    trace: &ColMatrix<E>,
    domain: &StarkDomain<Felt>,
    hash_fn: HashFn,
) -> (RowMatrix<E>, MerkleTree<H>, ColMatrix<E>) {
    // interpolate the execution trace
    #[cfg(feature = "std")]
    let now = Instant::now();
    let inv_twiddles = fft::get_inv_twiddles::<Felt>(trace.num_rows());
    let trace_polys = trace.columns().map(|col| {
        let mut poly = col.to_vec();
        fft::interpolate_poly(&mut poly, &inv_twiddles);
        poly
    });
    let helper = get_or_init_webgpu().await;

    // extend the execution trace and generate hashes on the gpu
    let lde_segments = FrozenVec::new();
    let lde_domain_size = domain.lde_domain_size();
    let num_base_columns = trace.num_base_cols();
    let mut row_hasher = RowHasher::<H>::new(&helper, lde_domain_size, num_base_columns, hash_fn);
    let mut lde_segment_generator = SegmentGenerator::new(trace_polys, domain);
    for segment in lde_segment_generator.gen_segment_iter() {
        let segment = lde_segments.push_get(Box::new(segment));
        row_hasher.update(segment);
    }
    let row_hashes = row_hasher.finish().await;
    let tree_nodes = helper.build_merkle_tree::<H>(&row_hashes, hash_fn).await;
    // aggregate segments at the same time as the GPU generates the merkle tree nodes
    let lde_segments = lde_segments.into_vec().into_iter().map(|p| *p).collect();
    let trace_lde = RowMatrix::from_segments(lde_segments, num_base_columns);
    let trace_polys = lde_segment_generator.into_polys().unwrap();
    let trace_tree = MerkleTree::from_raw_parts(tree_nodes, row_hashes).unwrap();
    #[cfg(feature = "std")]
    event!(
            Level::INFO,
            "Extended (on CPU) and committed (on GPU) to an execution trace of {} columns from 2^{} to 2^{} steps in {} ms",
            trace_polys.num_cols(),
            trace_polys.num_rows().ilog2(),
            trace_lde.num_rows().ilog2(),
            now.elapsed().as_millis()
        );

    (trace_lde, trace_tree, trace_polys)
}

// SEGMENT GENERATOR
// ================================================================================================

struct SegmentGenerator<'a, E, I, const N: usize>
where
    E: FieldElement<BaseField = Felt>,
    I: IntoIterator<Item = Vec<E>>,
{
    poly_iter: I::IntoIter,
    polys: Option<ColMatrix<E>>,
    poly_offset: usize,
    offsets: Vec<Felt>,
    domain: &'a StarkDomain<Felt>,
}

impl<'a, E, I, const N: usize> SegmentGenerator<'a, E, I, N>
where
    E: FieldElement<BaseField = Felt>,
    I: IntoIterator<Item = Vec<E>>,
{
    fn new(polys: I, domain: &'a StarkDomain<Felt>) -> Self {
        assert!(N > 0, "batch size N must be greater than zero");
        let poly_size = domain.trace_length();
        let lde_blowup = domain.trace_to_lde_blowup();
        let offsets = get_evaluation_offsets::<E>(poly_size, lde_blowup, domain.offset());
        Self {
            poly_iter: polys.into_iter(),
            polys: None,
            poly_offset: 0,
            offsets,
            domain,
        }
    }

    /// Returns the matrix of polynomials used to generate segments.
    fn into_polys(self) -> Option<ColMatrix<E>> {
        self.polys
    }

    /// Returns a segment generating iterator.
    fn gen_segment_iter(&mut self) -> SegmentIterator<'a, '_, E, I, N> {
        SegmentIterator(self)
    }

    /// Generates the next segment if it exists otherwise returns None.
    fn gen_next_segment(&mut self) -> Option<Segment<Felt, N>> {
        // initialize our col matrix
        if self.polys.is_none() {
            self.polys = Some(ColMatrix::new(vec![self.poly_iter.next()?]));
        }

        let offset = self.poly_offset;
        let polys = self.polys.as_mut().unwrap();
        while polys.num_base_cols() < offset + N {
            if let Some(poly) = self.poly_iter.next() {
                polys.merge_column(poly)
            } else {
                break;
            }
        }

        // terminate if there are no more segments to create
        if polys.num_base_cols() <= offset {
            return None;
        }

        let domain_size = self.domain.lde_domain_size();
        let mut data = vec![[Felt::ZERO; N]; domain_size];
        if polys.num_base_cols() < offset + N {
            // the segment will remain unfilled so we pad it with zeros
            data.fill([Felt::ZERO; N]);
        }

        let twiddles = self.domain.trace_twiddles();
        let segment = Segment::new_with_buffer(data, &*polys, offset, &self.offsets, twiddles);
        self.poly_offset += N;
        Some(segment)
    }
}

fn build_segment_queries<E, H, V>(
    segment_lde: &RowMatrix<E>,
    segment_vector_com: &V,
    positions: &[usize],
) -> Queries
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
{
    // for each position, get the corresponding row from the trace segment LDE and put all these
    // rows into a single vector
    let trace_states =
        positions.iter().map(|&pos| segment_lde.row(pos).to_vec()).collect::<Vec<_>>();

    // build a batch opening proof to the leaves specified by positions
    let trace_proof = segment_vector_com
        .open_many(positions)
        .expect("failed to generate a batch opening proof for trace queries");

    Queries::new::<H, E, V>(trace_proof.1, trace_states)
}

struct SegmentIterator<'a, 'b, E, I, const N: usize>(&'b mut SegmentGenerator<'a, E, I, N>)
where
    E: FieldElement<BaseField = Felt>,
    I: IntoIterator<Item = Vec<E>>;

impl<E, I, const N: usize> Iterator for SegmentIterator<'_, '_, E, I, N>
where
    E: FieldElement<BaseField = Felt>,
    I: IntoIterator<Item = Vec<E>>,
{
    type Item = Segment<Felt, N>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.gen_next_segment()
    }
}
