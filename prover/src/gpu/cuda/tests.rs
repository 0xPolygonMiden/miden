use alloc::vec::Vec;
use std::vec;

use air::{ProvingOptions, StarkField};
use miden_gpu::{
    cuda::util::{DIGEST_SIZE, RATE},
    HashFn,
};
use processor::{
    crypto::{Hasher, RpoDigest, RpoRandomCoin, Rpx256, RpxDigest, RpxRandomCoin},
    math::fft,
    StackInputs, StackOutputs,
};
use serial_test::serial;
use winter_prover::{crypto::Digest, CompositionPolyTrace, TraceLde};

use crate::{gpu::cuda::CudaExecutionProver, *};

fn build_trace_commitment_on_gpu_with_padding_matches_cpu<
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
    H: ElementHasher<BaseField = Felt> + Hasher<Digest = D> + Send + Sync,
    D: Digest + From<[Felt; DIGEST_SIZE]>,
>(
    hash_fn: HashFn,
) {
    let is_rpx = matches!(hash_fn, HashFn::Rpx256);

    let cpu_prover = create_test_prover::<R, H>(is_rpx);
    let gpu_prover = CudaExecutionProver::new(create_test_prover::<R, H>(is_rpx), hash_fn);
    let num_rows = 1 << 8;
    let trace_info = get_trace_info(1, num_rows);
    let trace = gen_random_trace(num_rows, RATE + 1);
    let domain = StarkDomain::from_twiddles(fft::get_twiddles(num_rows), 8, Felt::GENERATOR);

    let (cpu_trace_lde, cpu_polys) = cpu_prover.new_trace_lde::<Felt>(&trace_info, &trace, &domain);
    let (gpu_trace_lde, gpu_polys) = gpu_prover.new_trace_lde::<Felt>(&trace_info, &trace, &domain);

    assert_eq!(
        cpu_trace_lde.get_main_trace_commitment(),
        gpu_trace_lde.get_main_trace_commitment()
    );
    assert_eq!(
        cpu_polys.main_trace_polys().collect::<Vec<_>>(),
        gpu_polys.main_trace_polys().collect::<Vec<_>>()
    );
}

fn build_trace_commitment_on_gpu_without_padding_matches_cpu<
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
    H: ElementHasher<BaseField = Felt> + Hasher<Digest = D> + Send + Sync,
    D: Digest + From<[Felt; DIGEST_SIZE]>,
>(
    hash_fn: HashFn,
) {
    let is_rpx = matches!(hash_fn, HashFn::Rpx256);

    let cpu_prover = create_test_prover::<R, H>(is_rpx);
    let gpu_prover = CudaExecutionProver::new(create_test_prover::<R, H>(is_rpx), hash_fn);
    let num_rows = 1 << 8;
    let trace_info = get_trace_info(8, num_rows);
    let trace = gen_random_trace(num_rows, RATE);
    let domain = StarkDomain::from_twiddles(fft::get_twiddles(num_rows), 8, Felt::GENERATOR);

    let (cpu_trace_lde, cpu_polys) = cpu_prover.new_trace_lde::<Felt>(&trace_info, &trace, &domain);
    let (gpu_trace_lde, gpu_polys) = gpu_prover.new_trace_lde::<Felt>(&trace_info, &trace, &domain);

    assert_eq!(
        cpu_trace_lde.get_main_trace_commitment(),
        gpu_trace_lde.get_main_trace_commitment()
    );
    assert_eq!(
        cpu_polys.main_trace_polys().collect::<Vec<_>>(),
        gpu_polys.main_trace_polys().collect::<Vec<_>>()
    );
}

fn build_constraint_commitment_on_gpu_with_padding_matches_cpu<
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
    H: ElementHasher<BaseField = Felt> + Hasher<Digest = D> + Send + Sync,
    D: Digest + From<[Felt; DIGEST_SIZE]>,
>(
    hash_fn: HashFn,
) {
    let is_rpx = matches!(hash_fn, HashFn::Rpx256);

    let cpu_prover = create_test_prover::<R, H>(is_rpx);
    let gpu_prover = CudaExecutionProver::new(create_test_prover::<R, H>(is_rpx), hash_fn);
    let num_rows = 1 << 8;
    let ce_blowup_factor = 2;
    let values = get_random_values::<Felt>(num_rows * ce_blowup_factor);
    let domain = StarkDomain::from_twiddles(fft::get_twiddles(num_rows), 8, Felt::GENERATOR);

    let (commitment_cpu, composition_poly_cpu) = cpu_prover.build_constraint_commitment(
        CompositionPolyTrace::new(values.clone()),
        2,
        &domain,
    );
    let (commitment_gpu, composition_poly_gpu) =
        gpu_prover.build_constraint_commitment(CompositionPolyTrace::new(values), 2, &domain);

    assert_eq!(commitment_cpu.root(), commitment_gpu.root());
    assert_ne!(0, composition_poly_cpu.data().num_base_cols() % RATE);
    assert_eq!(composition_poly_cpu.into_columns(), composition_poly_gpu.into_columns());
}

fn build_constraint_commitment_on_gpu_without_padding_matches_cpu<
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
    H: ElementHasher<BaseField = Felt> + Hasher<Digest = D> + Send + Sync,
    D: Digest + From<[Felt; DIGEST_SIZE]>,
>(
    hash_fn: HashFn,
) {
    let is_rpx = matches!(hash_fn, HashFn::Rpx256);

    let cpu_prover = create_test_prover::<R, H>(is_rpx);
    let gpu_prover = CudaExecutionProver::new(create_test_prover::<R, H>(is_rpx), hash_fn);
    let num_rows = 1 << 8;
    let ce_blowup_factor = 8;
    let values = get_random_values::<Felt>(num_rows * ce_blowup_factor);
    let domain = StarkDomain::from_twiddles(fft::get_twiddles(num_rows), 8, Felt::GENERATOR);

    let (commitment_cpu, composition_poly_cpu) = cpu_prover.build_constraint_commitment(
        CompositionPolyTrace::new(values.clone()),
        8,
        &domain,
    );
    let (commitment_gpu, composition_poly_gpu) =
        gpu_prover.build_constraint_commitment(CompositionPolyTrace::new(values), 8, &domain);

    assert_eq!(commitment_cpu.root(), commitment_gpu.root());
    assert_eq!(0, composition_poly_cpu.data().num_base_cols() % RATE);
    assert_eq!(composition_poly_cpu.into_columns(), composition_poly_gpu.into_columns());
}

#[test]
#[serial]
fn rpo_build_trace_commitment_on_gpu_with_padding_matches_cpu() {
    build_trace_commitment_on_gpu_with_padding_matches_cpu::<RpoRandomCoin, Rpo256, RpoDigest>(
        HashFn::Rpo256,
    );
}

#[test]
#[serial]
fn rpx_build_trace_commitment_on_gpu_with_padding_matches_cpu() {
    build_trace_commitment_on_gpu_with_padding_matches_cpu::<RpxRandomCoin, Rpx256, RpxDigest>(
        HashFn::Rpx256,
    );
}

#[test]
#[serial]
fn rpo_build_trace_commitment_on_gpu_without_padding_matches_cpu() {
    build_trace_commitment_on_gpu_without_padding_matches_cpu::<RpoRandomCoin, Rpo256, RpoDigest>(
        HashFn::Rpo256,
    );
}

#[test]
#[serial]
fn rpx_build_trace_commitment_on_gpu_without_padding_matches_cpu() {
    build_trace_commitment_on_gpu_without_padding_matches_cpu::<RpxRandomCoin, Rpx256, RpxDigest>(
        HashFn::Rpx256,
    );
}

#[test]
#[serial]
fn rpo_build_constraint_commitment_on_gpu_with_padding_matches_cpu() {
    build_constraint_commitment_on_gpu_with_padding_matches_cpu::<RpoRandomCoin, Rpo256, RpoDigest>(
        HashFn::Rpo256,
    );
}

#[test]
#[serial]
fn rpx_build_constraint_commitment_on_gpu_with_padding_matches_cpu() {
    build_constraint_commitment_on_gpu_with_padding_matches_cpu::<RpxRandomCoin, Rpx256, RpxDigest>(
        HashFn::Rpx256,
    );
}

#[test]
#[serial]
fn rpo_build_constraint_commitment_on_gpu_without_padding_matches_cpu() {
    build_constraint_commitment_on_gpu_without_padding_matches_cpu::<
        RpoRandomCoin,
        Rpo256,
        RpoDigest,
    >(HashFn::Rpo256);
}

#[test]
#[serial]
fn rpx_build_constraint_commitment_on_gpu_without_padding_matches_cpu() {
    build_constraint_commitment_on_gpu_without_padding_matches_cpu::<
        RpxRandomCoin,
        Rpx256,
        RpxDigest,
    >(HashFn::Rpx256);
}

fn gen_random_trace(num_rows: usize, num_cols: usize) -> ColMatrix<Felt> {
    ColMatrix::new((0..num_cols as u64).map(|col| vec![Felt::new(col); num_rows]).collect())
}

fn get_random_values<E: FieldElement>(num_rows: usize) -> Vec<E> {
    (0..num_rows).map(|i| E::from(i as u32)).collect()
}

fn get_trace_info(num_cols: usize, num_rows: usize) -> TraceInfo {
    TraceInfo::new(num_cols, num_rows)
}

fn create_test_prover<
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
    H: ElementHasher<BaseField = Felt>,
>(
    use_rpx: bool,
) -> ExecutionProver<H, R> {
    if use_rpx {
        ExecutionProver::new(
            ProvingOptions::with_128_bit_security_rpx(),
            StackInputs::default(),
            StackOutputs::default(),
        )
    } else {
        ExecutionProver::new(
            ProvingOptions::with_128_bit_security(true),
            StackInputs::default(),
            StackOutputs::default(),
        )
    }
}
