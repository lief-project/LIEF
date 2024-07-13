/// This example shows how to inspect a DWARF debug info using LIEF's API

use std::process::{self, ExitCode};
use lief::dwarf::types::DwarfType;

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
    let mut file = std::fs::File::open(&path).expect("Can't open the file");

    let dbg = lief::dwarf::load(&path).unwrap_or_else(|| {
        process::exit(1);
    });

    for cu in dbg.compilation_units() {
        println!("Producer: {}", cu.producer());
        for func in cu.functions() {
            println!("name={}, linkage={}, address={}",
                func.name(), func.linkage_name(),
                func.address().unwrap_or(0)
            );
        }

        for var in cu.variables() {
            println!("name={}, address={}", var.name(), var.address().unwrap_or(0));
        }

        for ty in cu.types() {
            println!("name={}, size={}", ty.name().unwrap_or("".to_string()), ty.size().unwrap_or(0));
        }
    }

    dbg.function_by_name("_ZNSi4peekEv");
    dbg.function_by_name("std::basic_istream<char, std::char_traits<char> >::peek()");
    dbg.function_by_addr(0x137a70);

    dbg.variable_by_name("_ZNSt12out_of_rangeC1EPKc");
    dbg.variable_by_name("std::out_of_range::out_of_range(char const*)");
    dbg.variable_by_addr(0x137a70);

    println!("Can't process {}", path);
    ExitCode::FAILURE
}
