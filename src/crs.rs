use std::path::Path;

use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
use franklin_crypto::bellman::pairing::bn256::Bn256;
use tempfile::NamedTempFile;

pub fn create_crs(log2_size: usize, path: &Path) {
    let mut tmp_file = NamedTempFile::new().expect("fail to create a temporary file");
    let worker = franklin_crypto::bellman::worker::Worker::new();
    let crs = Crs::<Bn256, CrsForMonomialForm>::crs_42(1 << log2_size, &worker);
    crs.write(&mut tmp_file).expect("must serialize CRS");
    tmp_file
        .persist(path)
        .expect("fail to move crs file from temp file");
}
