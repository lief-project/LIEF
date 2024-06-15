/// Print the different entries of the PE's rich header

use std::process::{self, ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args();
    if args.len() != 2 {
        println!("Usage: {} <binary>", args.next().unwrap());
        return ExitCode::FAILURE;
    }

    let path = std::env::args().last().unwrap();
    let mut file = std::fs::File::open(&path).expect("Can't open the file");
    if let Some(lief::Binary::PE(pe)) = lief::Binary::from(&mut file) {
        let rich_header = pe.rich_header().unwrap_or_else(|| {
            println!("Rich header not found!");
            process::exit(0);
        });

        println!("Rich header key: 0x{:x}", rich_header.key());
        for entry in rich_header.entries() {
            println!("id: 0x{:04x} build_id: 0x{:04x} count: #{}",
                     entry.id(), entry.build_id(), entry.count());
        }

        return ExitCode::SUCCESS;
    }
    println!("Can't process {}", path);
    ExitCode::FAILURE
}
