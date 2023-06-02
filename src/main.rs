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

fn _gen_p_array() {
    let _p: [u32; 18];
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
fn main() {
    let (filename, password) = get_args();

    let Ok(bytes) = fs::read(&filename) else {
            println!("There was an error reading the file.");
            exit(2);
    };

    // Write our final stuff
    fs::write(format!("{}.bf", &filename), bytes).expect("error writing file");
}
