/// This example shows how to disassemble an ELF/PE/Mach-O binary using LIEF's extended API

use std::process::{self, ExitCode};
use lief::assembly::Instruction;

fn disassemble(target: &dyn lief::generic::Binary, address: u64) -> ExitCode {
    for inst in target.disassemble_address(address) {
        println!("{}", inst.to_string());
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    if !lief::is_extended() {
        println!("This example requires the extended version of LIEF")
    }

    let args = Vec::from_iter(std::env::args());
    if args.len() != 3 {
        println!("Usage: {} <binary> <address>", args[0]);
        return ExitCode::FAILURE;
    }

    let path = &args[1];
    let addr_str = &args[2];

    let mut addr: u64 = 0;
    if addr_str.starts_with("0x") {
        addr = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16).unwrap();
    } else {
        addr = u64::from_str_radix(&addr_str, 10).unwrap();
    }

    let bin = lief::Binary::parse(&path).expect("Can't parse the binary");
    match bin {
        lief::Binary::ELF(elf) => {
            return disassemble(&elf, addr);
        }

        lief::Binary::PE(pe) => {
            return disassemble(&pe, addr);
        }

        lief::Binary::MachO(fat) => {
            let fit = fat.iter().nth(0).unwrap();
            return disassemble(&fit, addr);
        }
    }
}
