//! This examples prints the `.dll` needed by a PE including whether it's using
//! ordinal-based imports.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args();
    if args.len() != 2 {
        println!("Usage: {} <binary>", args.next().unwrap());
        return ExitCode::FAILURE;
    }

    let path = std::env::args().last().unwrap();
    let mut file = std::fs::File::open(&path).expect("Can't open the file");
    if let Some(lief::Binary::PE(pe)) = lief::Binary::from(&mut file) {
        println!("Imports:");
        for imp in pe.imports() {
            let by_ordinal = imp.entries().any(|e| e.is_ordinal());
            let nb_entries = imp.entries().len();
            println!("  - {} [#imports: {}, by ordinal: {}]",
                     imp.name(), nb_entries, by_ordinal);
        }

        println!("Delay Imports:");
        for imp in pe.delay_imports() {
            let by_ordinal = imp.entries().any(|e| e.is_ordinal());
            let nb_entries = imp.entries().len();
            println!("  - {} [#imports: {}, by ordinal: {}]",
                     imp.name(), nb_entries, by_ordinal);
        }

        return ExitCode::SUCCESS;
    }
    println!("Can't process {}", path);
    ExitCode::FAILURE
}
