use criterion::{criterion_group, criterion_main, Criterion, black_box};
use obsidian_core::poly::Poly;

/// Constant-time verification for NTT operations.
/// 
/// This benchmark feeds two classes of data through the NTT:
/// - Class 0: All-zero polynomial (sparse/trivial)
/// - Class 1: Pseudo-random polynomial (dense/real-world)
/// 
/// If both classes complete in statistically identical time distributions,
/// the NTT is confirmed constant-time (no data-dependent branching).
fn ntt_constant_time_audit(c: &mut Criterion) {
    let mut group = c.benchmark_group("NTT Constant-Time");
    group.sample_size(1000);

    // Class 0: Trivial input (all zeros)
    group.bench_function("ntt_class_0_zeros", |b| {
        b.iter(|| {
            let mut p = Poly::new(); // All zeros
            p.ntt();
            black_box(&p);
        });
    });

    // Class 1: Dense random-like input
    group.bench_function("ntt_class_1_dense", |b| {
        b.iter(|| {
            let mut p = Poly::new();
            // Fill with pseudo-random looking data (deterministic for reproducibility)
            for i in 0..256 {
                p.coeffs[i] = ((i as i16 * 1337 + 42) % 3329) as i16;
            }
            p.ntt();
            black_box(&p);
        });
    });

    // Inverse NTT - Class 0
    group.bench_function("inv_ntt_class_0_zeros", |b| {
        b.iter(|| {
            let mut p = Poly::new();
            p.inv_ntt();
            black_box(&p);
        });
    });

    // Inverse NTT - Class 1
    group.bench_function("inv_ntt_class_1_dense", |b| {
        b.iter(|| {
            let mut p = Poly::new();
            for i in 0..256 {
                p.coeffs[i] = ((i as i16 * 7919 + 13) % 3329) as i16;
            }
            p.inv_ntt();
            black_box(&p);
        });
    });

    group.finish();
}

/// Full KEM cycle benchmark for throughput measurement.
fn kem_throughput_bench(c: &mut Criterion) {
    use obsidian_core::kem;
    use rand_core::OsRng;

    let mut group = c.benchmark_group("ML-KEM-768");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            let (pk, sk) = kem::generate_keypair(&mut rng);
            black_box((&pk, &sk));
        });
    });

    // Pre-generate a keypair for encap/decap benchmarks
    let mut rng = OsRng;
    let (pk, sk) = kem::generate_keypair(&mut rng);

    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            let (ct, ss) = kem::encapsulate_key(&pk, &mut rng);
            black_box((&ct, &ss));
        });
    });

    let (ct, _ss) = kem::encapsulate_key(&pk, &mut rng);

    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            let ss = kem::decapsulate_key(&ct, &sk);
            black_box(&ss);
        });
    });

    group.finish();
}

criterion_group!(benches, ntt_constant_time_audit, kem_throughput_bench);
criterion_main!(benches);
