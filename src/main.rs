// Main sources used
// https://www.schneier.com/academic/archives/1994/09/description_of_a_new.html
// https://en.wikipedia.org/wiki/Blowfish_(cipher)

pub(crate) use std::{env, fs, process::exit};

fn get_args() -> (String, String) {
    //! Gets the filename and password. Will exit the program if neither exist
    let args: Vec<String> = env::args().collect();

    let Some(filename) = args.get(1) else {
        println!("Please provide a filename as the first arg!");
        exit(1);
    };

    let Some(password) = args.get(2) else {
        println!("Please provide a password as the second arg!");
        exit(1);
    };

    if password.len() > 56 || password.len() == 0 {
        println!("Password must be 0 < n <= 56 characters long");
        exit(3);
    }

    (filename.to_string(), password.to_string())
}

fn quartets(n: &u32) -> (u8, u8, u8, u8) {
    //! Splits a u32 into four u8s
    (
        (n >> 8 * 3) as u8,
        (n >> 8 * 2) as u8,
        (n >> 8 * 1) as u8,
        *n as u8,
    )
}

fn split(n: &u64) -> (u32, u32) {
    //! Returns the two halves of the u64 as u32s
    //! First one is bitshifted to the right by 32, second one is &'d
    ((n >> 32) as u32, (n & 0xffffffff) as u32)
}

fn combine(l: &u32, r: &u32) -> u64 {
    //! Puts two u32s into one u64
    ((*l as u64) << 32) | (*r as u64)
}

fn f(n: &u32, s_boxes: &[[u32; 256]; 4]) -> u32 {
    //! This is literally called the f-function, it just messes up the number
    let (a, b, c, d) = quartets(n);
    ((s_boxes[0][a as usize] + s_boxes[1][b as usize]) ^ s_boxes[2][c as usize])
        + s_boxes[3][d as usize]
}

fn encrypt_block(block: u64, p_subkeys: &[u32; 18], s_boxes: &[[u32; 256]; 4]) -> u64 {
    let (mut left, mut right) = split(&block);

    for i in 0..16 {
        left ^= p_subkeys[i];
        right ^= f(&left, s_boxes);

        // Swap
        (left, right) = (right, left);
    }

    // Undo the last swap
    (left, right) = (right, left);

    right ^= p_subkeys[16];
    left ^= p_subkeys[17];

    combine(&left, &right)
}

fn generate_arrays(key: [u32; 14]) -> ([u32; 18], [[u32; 256]; 4]) {
    //! Creates the P subkeys and the S boxes based on the password and... PI.
    //! 14 * 32 = 448. P has more subkeys but those are generated dynamically
    //! Returns P, S.
    let mut p: [u32; 18] = [0; 18];
    let mut s: [[u32; 256]; 4] = [[0; 256]; 4];

    // Initialise with the digits of PI
    p[0] = 0x243f6a88;
    p[1] = 0x85a308d3;
    p[2] = 0x13198a2e;
    p[3] = 0x03707344;

    // Xor as much as we can with the key
    for i in 0..key.len() {
        p[i] ^= key[i];
    }

    // We now need to populate the rest of the stuff, using the previous calculations of blowfish
    let (l, r) = (0, 0);

    // First start with the Ps,
    // we go up 2 by 2 because one encryption fills 2 spots like
    // p[0] = left, p[1] = right
    for i in (0..p.len()).step_by(2) {
        (p[i], p[i + 1]) = split(&encrypt_block(combine(&l, &r), &p, &s));
    }

    // Now we do the Ss, same concept as before
    for b in 0..s.len() {
        for i in (0..s[0].len()).step_by(2) {
            (s[b][i], s[b][i + 1]) = split(&encrypt_block(combine(&l, &r), &p, &s));
        }
    }

    (p, s)
}

fn main() {
    let (filename, password) = get_args();

    let Ok(bytes) = fs::read(&filename) else {
            println!("There was an error reading the file.");
            exit(2);
    };

    // Write our final stuff
    fs::write(format!("{}.bf", &filename), bytes).expect("error writing file");
}
