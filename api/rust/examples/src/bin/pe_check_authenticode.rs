//! A simple example of validating PE authenticode signature in Rust

use lief::pe;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args();
    if args.len() != 2 {
        println!("Usage: {} <binary>", args.next().unwrap());
        return ExitCode::FAILURE;
    }

    let path = std::env::args().last().unwrap();
    let mut file = std::fs::File::open(path).expect("Can't open the file");
    if let Some(lief::Binary::PE(pe)) = lief::Binary::from(&mut file) {
        let result = pe.verify_signature(pe::signature::VerificationChecks::DEFAULT);
        if result.is_ok() {
            println!("Valid signature!");
        } else {
            println!("Signature not valid: {}", result);
        }
        return ExitCode::SUCCESS;
    }
    ExitCode::FAILURE
}
