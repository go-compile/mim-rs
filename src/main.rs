use byteorder::{BigEndian, ByteOrder};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

const COLOURS: [[u8; 3]; 16] = [
    [0, 0, 0],       // black
    [194, 54, 33],   // Red
    [37, 188, 36],   // Green
    [173, 173, 39],  // Yellow
    [73, 46, 225],   // Blue
    [211, 56, 211],  // Magenta
    [51, 187, 200],  // Cyan
    [203, 204, 205], // White
    [129, 131, 131], // Gray
    [252, 57, 31],   // Bright Red
    [49, 231, 34],   // Bright Green
    [234, 236, 35],  // Bright Yellow
    [88, 51, 255],   // Bright Blue
    [249, 53, 248],  // Bright Magenta
    [20, 240, 240],  // Bright Cyan
    [233, 235, 235], // Bright Whites
];

fn main() {
    let mut hasher = Sha256::new();
    hasher.update("certificate contents would typically go here");
    let fingerprint = hasher.finalize();

    let moz = Mozaic::new(&fingerprint);

    println!("Fingerprint: {:X?}", &fingerprint);
    println!("{}", &moz.ansi());
}

pub struct Mozaic {
    data: [u8; 32],
}

impl Mozaic {
    pub fn new(data: &[u8]) -> Self {
        let mut moz = Mozaic { data: [0u8; 32] };

        let hk = Hkdf::<Sha256>::new(None, &data);
        hk.expand(&[0u8; 0], &mut moz.data)
            .expect("hkdf to provide 32 bytes");

        return moz;
    }

    pub fn ansi(&self) -> String {
        let rows = 8;
        let mut output = "".to_string();

        // assign a uint16 for reading byte in Big Endian byte order.
        // It would be preferred to use a u8 buffer but there is not a option
        // to read u8s in the byteorder crate.
        let mut u16buf = [0u8; 2];

        // iterate over the digest
        for i in 0..32 {
            if i % rows == 0 && i != 0 {
                // if at end of row add new line
                output += "\r\n"
            } else if i % 2 == 1 && i != 0 {
                // per row, every fourth byte add space and create parallel square

                let (l, r) = split_byte(&mut u16buf, self.data[i]);

                // add left and right plus a space after ANSI reset
                output += &(ansi_rgb(l) + "  " + &(ansi_rgb(r) + &"  \x1b[0m  "));
                continue;
            }

            let (l, r) = split_byte(&mut u16buf, self.data[i]);
            output += &(ansi_rgb(l) + "  " + &(ansi_rgb(r)) + "  \x1b[0m");
        }

        return output + "\x1b[0m";
    }
}

fn split_byte(u16buf: &mut [u8; 2], b: u8) -> ([u8; 3], [u8; 3]) {
    // shift left most 4 bits to end of byte, filling first 4 bits with zeros
	let l = b >> 4;
    // shift right 4 then back 4 to clear the right most 4 bits then shift back
    let r = b << 4 >> 4;

    // assign left most byte in Little the left 4bit buffer
    u16buf[1] = l;
    let li = (BigEndian::read_u16(u16buf)) as usize;

    // assign left most byte in Little the right 4bit buffer
    u16buf[1] = r;
    let ri = (BigEndian::read_u16(u16buf)) as usize;

    return (COLOURS[li], COLOURS[ri]);
}

// ansi_RGB returns a ANSI escape sequence for the colour
fn ansi_rgb(rgb: [u8; 3]) -> String {
    return format!(
        "\x1b[38;2;{};{};{};48;2;{};{};{}m",
        rgb[0], rgb[1], rgb[2], rgb[0], rgb[1], rgb[2]
    );
}
