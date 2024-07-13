/// This example shows how to inspect a Objective-C info using LIEF's API

use std::process::{self, ExitCode};

fn main() -> ExitCode {
    if !lief::is_extended() {
        println!("This example requires the extended version of LIEF")
    }
    let mut args = std::env::args();
    if args.len() != 2 {
        println!("Usage: {} <binary>", args.next().unwrap());
        return ExitCode::FAILURE;
    }

    let path = std::env::args().last().unwrap();

    let Some(lief::Binary::MachO(fat)) = lief::Binary::parse(&path) else { process::exit(1); };
    let Some(bin) = fat.iter().next() else { process::exit(1); };
    let Some(metadata) = bin.objc_metadata() else { process::exit(1); };

    for class in metadata.classes() {
        println!("name={}", class.name());
        for method in class.methods() {
            println!("  method.name={}", method.name());
        }
    }
    println!("{}", metadata.to_decl());



    ExitCode::FAILURE

}
