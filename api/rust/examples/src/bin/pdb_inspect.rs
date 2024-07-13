/// This example shows how to inspect a PDB file using LIEF's API

use std::process::{self, ExitCode};
use lief::pdb::types::classlike::ClassLike;

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
    let pdb = lief::pdb::load(&path).unwrap_or_else(|| {
        process::exit(1);
    });
    println!("age={}, guid={}", pdb.age(), pdb.guid());

    for symbol in pdb.public_symbols() {
        println!("name={}, section={}, RVA={}",
            symbol.name(), symbol.section_name().unwrap_or("".to_string()),
            symbol.rva());
    }

    for ty in pdb.types() {
        if let lief::pdb::Type::Class(clazz) = ty {
            println!("Class[name]={}", clazz.name());
        }
    }

    for cu in pdb.compilation_units() {
        println!("module={}", cu.module_name());
        for src in cu.sources() {
            println!("  - {}", src);
        }

        for func in cu.functions() {
            println!("name={}, section={}, RVA={}, code_size={}",
                func.name(), func.section_name(), func.rva(), func.code_size()
            );
        }
    }


    println!("Can't process {}", path);
    ExitCode::FAILURE
}
