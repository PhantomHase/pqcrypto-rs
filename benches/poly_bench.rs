use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pqcrypto_core::poly::Poly;
use pqcrypto_core::ntt::poly_mul;
use pqcrypto_core::sampling::{sample_cbd, sample_uniform};
use pqcrypto_core::{Q, N};

fn bench_poly_mul(c: &mut Criterion) {
    let mut a = Poly::zero();
    let mut b = Poly::zero();
    for i in 0..N {
        a.coeffs[i] = (i as u16 * 13 + 7) % Q;
        b.coeffs[i] = (i as u16 * 17 + 11) % Q;
    }

    c.bench_function("poly_mul_schoolbook", |bench| {
        bench.iter(|| poly_mul(black_box(&a), black_box(&b)))
    });
}

fn bench_poly_add(c: &mut Criterion) {
    let mut a = Poly::zero();
    let mut b = Poly::zero();
    for i in 0..N {
        a.coeffs[i] = (i as u16 * 13 + 7) % Q;
        b.coeffs[i] = (i as u16 * 17 + 11) % Q;
    }

    c.bench_function("poly_add", |bench| {
        bench.iter(|| black_box(&a).add(black_box(&b)))
    });
}

fn bench_sample_cbd(c: &mut Criterion) {
    let bytes = vec![0x42u8; 2 * 256 / 4]; // eta=2
    c.bench_function("sample_cbd_eta2", |bench| {
        bench.iter(|| sample_cbd(black_box(2), black_box(&bytes)))
    });
}

fn bench_sample_uniform(c: &mut Criterion) {
    let mut bytes = Vec::new();
    for i in 0..1000u16 {
        bytes.extend_from_slice(&i.to_le_bytes());
    }
    c.bench_function("sample_uniform", |bench| {
        bench.iter(|| sample_uniform(black_box(&bytes)))
    });
}

criterion_group!(benches, bench_poly_mul, bench_poly_add, bench_sample_cbd, bench_sample_uniform);
criterion_main!(benches);
