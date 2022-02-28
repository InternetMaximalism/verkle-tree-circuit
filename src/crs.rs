#[cfg(test)]
mod crs_tests {
    use std::fs::File;

    use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
    use franklin_crypto::bellman::pairing::bn256::Bn256;

    fn create_crs_for_log2_of_size(log2_n: usize) -> Crs<Bn256, CrsForMonomialForm> {
        let worker = franklin_crypto::bellman::worker::Worker::new();

        Crs::<Bn256, CrsForMonomialForm>::crs_42(1 << log2_n, &worker)
    }

    #[test]
    fn test_crs_serialization() {
        let path = std::env::current_dir().unwrap();
        let path = path.join("tests/crs");
        let mut file = File::create(path).unwrap();
        let crs = create_crs_for_log2_of_size(23); // < 8388608 constraints
        crs.write(&mut file).expect("must serialize CRS");
    }
}
