use mim::{Mozaic};
use sha2::{Sha256,Digest};
use hex;

fn main() {
	// create the fingerprint in the typical way
	let mut hasher = Sha256::new();
    hasher.update("certificate contents would typically go here");
    let fingerprint = hasher.finalize();

	// provide the fingerprint to MIM
    let moz = Mozaic::new(&fingerprint);

	// print fingerprint
    println!("Fingerprint: {}", hex::encode(&fingerprint));

	// print Mozaic as ASNI
    println!("\n{}", &moz.ansi());
}