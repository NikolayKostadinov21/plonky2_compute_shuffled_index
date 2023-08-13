extern crate sha2;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use sha2::{Digest, Sha256};
use std::cmp;

const SHUFFLE_ROUND_COUNT: usize = 90;

pub fn compute_shuffled_index(index: &mut u64, index_count: u64, seed: [u8; 32]) -> u64 {
    assert!(*index < index_count);

    for current_round in 0..SHUFFLE_ROUND_COUNT {
        let mut bytes_current_round: [u8; 32] = [0; 32];
        bytes_current_round[0] = current_round as u8;

        let pivot = u64::from_be_bytes(Sha256::digest([seed, bytes_current_round].concat())[0..8].try_into().unwrap()) % index_count;
        let flip = (pivot + index_count - *index) % index_count;

        let position = cmp::max(flip, *index);
        let mut bytes_position: [u8; 32] = [0; 32];
        bytes_position[0] = position as u8;

        let source = Sha256::digest(
            [
                seed,
                bytes_current_round,
                bytes_position
            ].concat()
        );

        let byte = (source[(position as usize % 256) / 8]) as u8;
        let bit = (byte >> (position as usize % 8)) % 2;

        if bit == 1 {
           *index = flip;
        }
    }

    *index
}

fn main() {
    const D: usize = 2;
    const N: usize = 32;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let circuit_config: CircuitConfig = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(circuit_config);

    // The arithmetic circuit.
    let mut index = builder.add_virtual_target();
    let index_count = builder.add_virtual_target();
    let seed: [plonky2::iop::target::Target; N] = builder.add_virtual_target_arr();
    
    for current_round in 0..SHUFFLE_ROUND_COUNT {
        let current_round_target = builder.constant(F::from_canonical_u8(current_round as u8));
        let mut current_round_to_be_hashed: [plonky2::iop::target::Target; N] = builder.add_virtual_target_arr();
        current_round_to_be_hashed[0] = current_round_target;

        let mut to_be_hashed_seed_round: [plonky2::iop::target::Target; N*2] = builder.add_virtual_target_arr();
        to_be_hashed_seed_round[..N].copy_from_slice(&seed);
        to_be_hashed_seed_round[N..].copy_from_slice(&current_round_to_be_hashed);
        let (_, to_be_hashed, _) = unsafe { to_be_hashed_seed_round.align_to_mut::<u8>() };

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(to_be_hashed);
        let hash = &mut sha256_hasher.finalize();

        let hash_to_num = builder.constant(F::from_canonical_u64(u64::from_be_bytes(hash[0..8].try_into().unwrap())));
        let quotient = builder.div(hash_to_num, index_count);
        let quot_times_index_count = builder.mul(quotient, index_count);
        let pivot = builder.sub(hash_to_num, quot_times_index_count);

        let sum_pivot_index_count = builder.add(pivot, index_count);
        let sum_pivot_icounter_index = builder.sub(sum_pivot_index_count, index);
        let pivot_quotient = builder.div(sum_pivot_icounter_index, index_count);
        let quotient_times_divisor = builder.mul(index_count, pivot_quotient);
        let flip = builder.sub(sum_pivot_icounter_index, quotient_times_divisor);

        // position = max(index, flip)
        let position = 1;

        let position_target = builder.constant(F::from_canonical_u32((position as usize / 256) as u32));
        let mut position_to_be_hashed: [plonky2::iop::target::Target; N] = builder.add_virtual_target_arr();
        position_to_be_hashed[0] = position_target;

        let mut source_to_be_hashed: [plonky2::iop::target::Target; N*3] = builder.add_virtual_target_arr();
        source_to_be_hashed[..N].copy_from_slice(&seed);
        source_to_be_hashed[N..N*2].copy_from_slice(&current_round_to_be_hashed);
        source_to_be_hashed[N*2..].copy_from_slice(&position_to_be_hashed);
        let (_, _source_to_be_hashed, _) = unsafe { source_to_be_hashed.align_to_mut::<u8>() };

        let mut source_hasher = Sha256::new();
        source_hasher.update(_source_to_be_hashed);
        let source = &mut source_hasher.finalize();

        let byte = (source[(position as usize % 256) / 8]) as u8;
        let bit = (byte >> (position as usize % 8)) % 2;
        if bit == 1 {
            index = flip;
        }
    }

    builder.register_public_input(index);
    builder.register_public_input(index_count);
    builder.register_public_inputs(&seed);

    // Providing the initial values.
    let mut pw = PartialWitness::new();
    pw.set_target(index, F::from_canonical_u64(2));
    pw.set_target(index_count, F::from_canonical_u64(888));
    pw.set_target_arr(&seed, &[F::from_canonical_u64(27), F::from_canonical_u64(26), F::from_canonical_u64(30),
    F::from_canonical_u64(6), F::from_canonical_u64(9), F::from_canonical_u64(28), F::from_canonical_u64(13),
    F::from_canonical_u64(0), F::from_canonical_u64(5), F::from_canonical_u64(8), F::from_canonical_u64(14),
    F::from_canonical_u64(12), F::from_canonical_u64(23), F::from_canonical_u64(21), F::from_canonical_u64(16), F::from_canonical_u64(4),
    F::from_canonical_u64(22), F::from_canonical_u64(31), F::from_canonical_u64(3), F::from_canonical_u64(10), F::from_canonical_u64(19),
    F::from_canonical_u64(11), F::from_canonical_u64(32), F::from_canonical_u64(20), F::from_canonical_u64(7), F::from_canonical_u64(1),
    F::from_canonical_u64(25), F::from_canonical_u64(18), F::from_canonical_u64(17), F::from_canonical_u64(15), F::from_canonical_u64(2),
    F::from_canonical_u64(24)
    ]);

    let data = builder.build::<C>();
    let proof = data.prove(pw);
    println!("Proof: {:x?}", proof);

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_shuffled_correctly() {
        let mut index = 18446744073709;
        let index_count = 1844674407370955161;
        let seed = [27, 26, 30, 6, 9, 28, 13, 0, 5, 8, 14, 12, 23, 21, 16, 4, 22, 31, 3, 10, 19, 11, 32, 20, 7, 1, 25, 18, 17, 15, 2, 24];
        assert_eq!(compute_shuffled_index(&mut index, index_count, seed), 1520772600844238733);
    }
    
    #[test]
    #[should_panic]
    fn is_index_count_smaller() {
        let mut index = 1844674407370955161;
        let index_count = 18446744073709;
        let seed = [27, 26, 30, 6, 9, 28, 13, 0, 5, 8, 14, 12, 23, 21, 16, 4, 22, 31, 3, 10, 19, 11, 32, 20, 7, 1, 25, 18, 17, 15, 2, 24];
        compute_shuffled_index(&mut index, index_count, seed);
    }
}