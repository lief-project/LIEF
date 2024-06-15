/// This example lists all the dependencies of an ELF file as well as the required symbol
/// versions. This can be used to assess if an ELF executable can run on a given Linux distribution

use std::process::ExitCode;
use lief::elf::dynamic;

fn main() -> ExitCode {
    let mut args = std::env::args();
    if args.len() != 2 {
        println!("Usage: {} <binary>", args.next().unwrap());
        return ExitCode::FAILURE;
    }

    let path = std::env::args().last().unwrap();
    let mut file = std::fs::File::open(&path).expect("Can't open the file");
    if let Some(lief::Binary::ELF(elf)) = lief::Binary::from(&mut file) {
        println!("Dependencies:");
        for entry in elf.dynamic_entries() {
            if let dynamic::Entries::Library(lib) = entry {
                println!("  - {}", lib.name());
            }
        }
        println!("Versions:");
        for version in elf.symbols_version_requirement() {
            println!("  From {}", version.name());
            for aux in version.auxiliary_symbols() {
                println!("    - {}", aux.name());
            }
        }

        return ExitCode::SUCCESS;
    }
    println!("Can't process {}", path);
    ExitCode::FAILURE
}
