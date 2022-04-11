use std::{fs::File, path::Path};

use franklin_crypto::bellman::{
    kate_commitment::{Crs, CrsForMonomialForm},
    pairing::bn256::Bn256,
};

pub fn open_crs_for_log2_of_size(_log2_n: usize) -> Crs<Bn256, CrsForMonomialForm> {
    let full_path = Path::new("./test_cases").join("crs14");
    println!("Opening {}", full_path.to_string_lossy());
    let file = File::open(&full_path).unwrap();
    let reader = std::io::BufReader::with_capacity(1 << 24, file);
    let crs = Crs::<Bn256, CrsForMonomialForm>::read(reader).unwrap();
    println!("Load {}", full_path.to_string_lossy());

    crs
}
