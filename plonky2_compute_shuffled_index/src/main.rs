extern crate sha2;

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

fn main() {}
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