use dudect_bencher::{ctbench_main, Class, CtRunner};
use obsidian_core::poly::Poly;
use rand_core::RngCore;
use dudect_bencher::rand::Rng;

mod rand_chacha {
    pub mod chacha {
        pub type ChaCha20Rng = ::rand_chacha::ChaCha20Rng;
    }
}

fn bench_ntt(runner: &mut CtRunner, rng: &mut rand_chacha::chacha::ChaCha20Rng) {
    let mut inputs = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..1000 {
        // Class::Left: All-zero polynomial (sparse/trivial)
        inputs.push(Poly::new());
        classes.push(Class::Left);

        // Class::Right: Pseudo-random polynomial (dense/real-world)
        let mut p = Poly::new();
        for i in 0..256 {
            p.coeffs[i] = (rng.next_u32() % 3329) as i16;
        }
        inputs.push(p);
        classes.push(Class::Right);
    }

    for (class, p) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            let mut p_copy = p;
            p_copy.ntt();
        });
    }
}

fn bench_inv_ntt(runner: &mut CtRunner, rng: &mut rand_chacha::chacha::ChaCha20Rng) {
    let mut inputs = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..1000 {
        inputs.push(Poly::new());
        classes.push(Class::Left);

        let mut p = Poly::new();
        for i in 0..256 {
            p.coeffs[i] = (rng.next_u32() % 3329) as i16;
        }
        inputs.push(p);
        classes.push(Class::Right);
    }

    for (class, p) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            let mut p_copy = p;
            p_copy.inv_ntt();
        });
    }
}

ctbench_main!(bench_ntt, bench_inv_ntt);
