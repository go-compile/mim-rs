# MIM-RS (Minimal Identity Mozaic)

<div align="center">
	<img width="150px" src=".github/rust.svg" />
	
*A rusty implementation.*
</div>


MIM is a Hash Visualization format utilising 4x4 colour matrixes. This provides a quick and easy method to compare fingerprints, e.g. SSH keys, x509 certs etc.

[\[ Go Implementation \]](https://github.com/go-compile/mim)
[\[ Rust Implementation \]](https://github.com/go-compile/mim-rs)

## Properties
- Pre Image Resistant
- Fixed Length Output
- Collision Resistant
- Fast & Efficient
- Identical Colours Cross Platform

## Output

MIM outputs coloured **ANSI escape codes**.

![Mim Rust Image](.github/mim.png)

## Example

```rust
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
```