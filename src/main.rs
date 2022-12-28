use hkdf::Hkdf;
use sha2::{Sha256, Digest};


fn main() {
	let mut hasher = Sha256::new();
	hasher.update("certificate contents would typically go here");
	let fingerprint = hasher.finalize();

	let moz = Mozaic::new(&fingerprint);

	println!("Fingerprint: {:X?}", &fingerprint);
	println!("HKDF'ed: {:X?}", &moz.data);
}

struct Mozaic {
    data: [u8; 32],
}

impl Mozaic {
    pub fn new(data: &[u8]) -> Self {

		let mut moz = Mozaic{
			data: [0u8; 32]
		};

		let hk = Hkdf::<Sha256>::new(None, &data);
		hk.expand(&[0u8;0], &mut moz.data).expect("hkdf to provide 32 bytes");

        return moz;
    }
}
