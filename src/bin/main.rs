use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W1NoOff;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W1Off10;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W2NoOff;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W2Off10;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W4NoOff;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W4Off10;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W8NoOff;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W8Off10;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W2;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W4;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W8;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W1NoOff;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W1Off10;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W2NoOff;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W2Off10;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W4NoOff;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W4Off10;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W8NoOff;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W8Off10;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::winternitz::SIGWinternitzLifetime20W1;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::winternitz::SIGWinternitzLifetime20W2;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::winternitz::SIGWinternitzLifetime20W4;
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::winternitz::SIGWinternitzLifetime20W8;
use hashsig::signature::SignatureScheme;
use rand::rngs::ThreadRng;
use rand::Rng;
use rand::thread_rng;
use std::time::Instant;

// Black-box utility to prevent optimizations
#[inline(never)]
fn black_box<T>(dummy: T) -> T {
    unsafe { std::ptr::read_volatile(&dummy) }
}

// Function to measure execution time
fn measure_gen_time<T: SignatureScheme, R: Rng>(description: &str, rng: &mut R) {
    let start = Instant::now();
    let result = T::gen(rng);
    black_box(result); // Prevent optimization
    let duration = start.elapsed();
    println!("{} took {:?}", description, duration);
}

// Main function to run the program
fn main() {
    let mut rng = thread_rng();

    // Lifetime 2^18 - Winternitz
    measure_gen_time::<SIGWinternitzLifetime18W1, ThreadRng>(
        "Poseidon - L 18 - Winternitz - w 1 - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGWinternitzLifetime18W2, ThreadRng>(
        "Poseidon - L 18 - Winternitz - w 2 - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGWinternitzLifetime18W4, ThreadRng>(
        "Poseidon - L 18 - Winternitz - w 4 - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGWinternitzLifetime18W8, ThreadRng>(
        "Poseidon - L 18 - Winternitz - w 8 - Gen",
        &mut rng,
    );

    // Lifetime 2^20 - Winternitz
    measure_gen_time::<SIGWinternitzLifetime20W1, ThreadRng>(
        "Poseidon - L 20 - Winternitz - w 1 - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGWinternitzLifetime20W2, ThreadRng>(
        "Poseidon - L 20 - Winternitz - w 2 - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGWinternitzLifetime20W4, ThreadRng>(
        "Poseidon - L 20 - Winternitz - w 4 - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGWinternitzLifetime20W8, ThreadRng>(
        "Poseidon - L 20 - Winternitz - w 8 - Gen",
        &mut rng,
    );

    // Lifetime 2^18 - Target Sum
    measure_gen_time::<SIGTargetSumLifetime18W1NoOff, ThreadRng>(
        "Poseidon - L 18 - Target Sum - w 1 - No Off - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGTargetSumLifetime18W1Off10, ThreadRng>(
        "Poseidon - L 18 - Target Sum - w 1 - 10% Off - Gen",
        &mut rng,
    );

    measure_gen_time::<SIGTargetSumLifetime18W2NoOff, ThreadRng>(
        "Poseidon - L 18 - Target Sum - w 2 - No Off - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGTargetSumLifetime18W2Off10, ThreadRng>(
        "Poseidon - L 18 - Target Sum - w 2 - 10% Off - Gen",
        &mut rng,
    );

    measure_gen_time::<SIGTargetSumLifetime18W4NoOff, ThreadRng>(
        "Poseidon - L 18 - Target Sum - w 4 - No Off - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGTargetSumLifetime18W4Off10, ThreadRng>(
        "Poseidon - L 18 - Target Sum - w 4 - 10% Off - Gen",
        &mut rng,
    );

    measure_gen_time::<SIGTargetSumLifetime18W8NoOff, ThreadRng>(
        "Poseidon - L 18 - Target Sum - w 8 - No Off - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGTargetSumLifetime18W8Off10, ThreadRng>(
        "Poseidon - L 18 - Target Sum - w 8 - 10% Off - Gen",
        &mut rng,
    );

    // Lifetime 2^20 - Target Sum
    measure_gen_time::<SIGTargetSumLifetime20W1NoOff, ThreadRng>(
        "Poseidon - L 20 - Target Sum - w 1 - No Off - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGTargetSumLifetime20W1Off10, ThreadRng>(
        "Poseidon - L 20 - Target Sum - w 1 - 10% Off - Gen",
        &mut rng,
    );

    measure_gen_time::<SIGTargetSumLifetime20W2NoOff, ThreadRng>(
        "Poseidon - L 20 - Target Sum - w 2 - No Off - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGTargetSumLifetime20W2Off10, ThreadRng>(
        "Poseidon - L 20 - Target Sum - w 2 - 10% Off - Gen",
        &mut rng,
    );

    measure_gen_time::<SIGTargetSumLifetime20W4NoOff, ThreadRng>(
        "Poseidon - L 20 - Target Sum - w 4 - No Off - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGTargetSumLifetime20W4Off10, ThreadRng>(
        "Poseidon - L 20 - Target Sum - w 4 - 10% Off - Gen",
        &mut rng,
    );

    measure_gen_time::<SIGTargetSumLifetime20W8NoOff, ThreadRng>(
        "Poseidon - L 20 - Target Sum - w 8 - No Off - Gen",
        &mut rng,
    );
    measure_gen_time::<SIGTargetSumLifetime20W8Off10, ThreadRng>(
        "Poseidon - L 20 - Target Sum - w 8 - 10% Off - Gen",
        &mut rng,
    );
}
