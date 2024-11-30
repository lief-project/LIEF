mod utils;
use lief;
use lief::assembly::{Instruction, Instructions};
use lief::dwarf::types::{Base, ClassLike, DwarfType};
use lief::dwarf::{Parameter, Scope, Type};
use lief::generic::{Binary, Section};

use std::path::{Path, PathBuf};
fn get_binary(name: &str) -> lief::Binary {
    let path = utils::get_sample(Path::new(name)).unwrap();
    let path_str = path.to_str().unwrap();

    let bin = lief::Binary::parse(path_str);
    bin.unwrap()
}

fn should_skip(inst: &lief::assembly::Instructions) -> bool {
    if let lief::assembly::Instructions::X86(x86) = inst {
        if let opcode = x86.opcode() {
            return opcode == lief::assembly::x86::Opcode::JCC_1 ||
                   opcode == lief::assembly::x86::Opcode::JCC_2 ||
                   opcode == lief::assembly::x86::Opcode::JCC_4 ||
                   opcode == lief::assembly::x86::Opcode::JMP_1 ||
                   opcode == lief::assembly::x86::Opcode::JMP_2 ||
                   opcode == lief::assembly::x86::Opcode::JMP_4 ||
                   opcode == lief::assembly::x86::Opcode::CALL64pcrel32 ||
                   opcode == lief::assembly::x86::Opcode::CALLpcrel32;
        }
    }
    return false;
}

fn assemble_inst(name: &str, bin: &mut dyn lief::generic::Binary, inst: &lief::assembly::Instructions) {
    println!("{}: {:02X?}", inst.to_string(), inst.raw());
    if should_skip(inst) {
        return;
    }
    let raw = bin.assemble(inst.address(), &inst.to_string_no_address());
    let new_inst = bin.disassemble_slice(raw.as_slice(), inst.address()).next().unwrap();
    assert_eq!(new_inst.to_string_no_address(), inst.to_string_no_address());
}

fn reassemble_from(name: &str, address: u64, count: usize) {
    let mut bin = get_binary(name);
    match bin {
        lief::Binary::ELF(mut elf) => {
            let insts = elf.disassemble_address(address)
                .take(count)
                .collect::<Vec<lief::assembly::Instructions>>();

            for inst in insts {
                assemble_inst(name, &mut elf, &inst);
            }
        },

        lief::Binary::PE(mut pe) => {
            let insts = pe.disassemble_address(address)
                .take(count)
                .collect::<Vec<lief::assembly::Instructions>>();

            for inst in insts {
                assemble_inst(name, &mut pe, &inst);
            }
        },

        lief::Binary::MachO(fat) => {
            for mut macho in fat.iter() {
                let insts = macho.disassemble_address(address)
                    .take(count)
                    .collect::<Vec<lief::assembly::Instructions>>();

                for inst in insts {
                    assemble_inst(name, &mut macho, &inst);
                }
            }
        },
    }

}
#[test]
fn test_api() {
    if !lief::is_extended() {
        return;
    }

    reassemble_from("MachO/ios17/DebugHierarchyKit", 0x16650, 100); // ARM64E
    //reassemble_from("MachO/macho-issue-1110.bin", 0x00000b10, 10); // PPC
    reassemble_from("PE/ntoskrnl.exe", 0x140200000, 300);
    reassemble_from("ELF/ELF32_x86_library_libshellx.so", 0x000010c0, 300);
    //reassemble_from("ELF/libmonochrome-armv7.so", 0x0468b701, 300); // Thumb
    //reassemble_from("ELF/i872_risv.elf", 0x80000000, 300);
}
