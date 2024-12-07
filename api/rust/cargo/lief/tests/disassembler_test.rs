mod utils;
use lief;
use lief::assembly::x86;
use lief::assembly::x86::Operand;
use lief::assembly::{Instruction, Instructions};
use lief::dwarf::types::{Base, ClassLike, DwarfType};
use lief::dwarf::{Parameter, Scope, Type};
use lief::generic::{Binary, Section};

use std::path::{Path, PathBuf};

fn process_instruction(inst: &lief::assembly::Instructions) {
    //println!("{} {:#02x?}", inst.to_string(), inst.raw());
    println!("{}", inst.to_string());
    format!(
        "{} {} {} {}",
        inst.address(),
        inst.size(),
        inst.raw().len(),
        inst.mnemonic()
    );
    format!("{}", inst.to_string());
    format!(
        "{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        inst.is_call(),
        inst.is_syscall(),
        inst.is_terminator(),
        inst.is_branch(),
        inst.is_memory_access(),
        inst.is_move_reg(),
        inst.is_add(),
        inst.is_trap(),
        inst.is_barrier(),
        inst.is_return(),
        inst.is_indirect_branch(),
        inst.is_conditional_branch(),
        inst.is_compare(),
        inst.is_move_immediate(),
        inst.is_bitcast(),
        inst.memory_access(),
        inst.branch_target().unwrap_or(0)
    );
    match inst {
        Instructions::AArch64(variant) => {
            format!("{:?}", variant.opcode());
        }
        Instructions::ARM(variant) => {
            format!("{:?}", variant.opcode());
        }
        Instructions::X86(variant) => {
            //println!("{}", inst.to_string());
            format!("{:?}", variant.opcode());
            for op in variant.operands() {
                format!("{}", op.to_string());
                match op {
                    x86::Operands::Reg(reg) => {
                        format!("{:?}", reg.value());
                    }

                    x86::Operands::Imm(imm) => {
                        format!("{}", imm.value());
                    }

                    x86::Operands::PCRelative(pcr) => {
                        format!("{}", pcr.value());
                    }

                    x86::Operands::Mem(mem) => {
                        format!(
                            "{:?}{:?}{:?}{}{}",
                            mem.base(),
                            mem.scaled_register(),
                            mem.segment_register(),
                            mem.scale(),
                            mem.displacement()
                        );
                    }
                    x86::Operands::Unknown(_) => {}
                }
            }
        }
        Instructions::Mips(variant) => {
            format!("{:?}", variant.opcode());
        }
        Instructions::PowerPC(variant) => {
            format!("{:?}", variant.opcode());
        }
        Instructions::EBPF(variant) => {
            format!("{:?}", variant.opcode());
        }
        Instructions::RiscV(variant) => {
            format!("{:?}", variant.opcode());
        }
        Instructions::Generic(_) => {}
    }
}

fn get_binary(name: &str) -> lief::Binary {
    let path = utils::get_sample(Path::new(name)).unwrap();
    let path_str = path.to_str().unwrap();

    let bin = lief::Binary::parse(path_str);
    bin.unwrap()
}

fn disa_from_address(name: &str, address: u64) {
    let bin = get_binary(name);

    match bin {
        lief::Binary::ELF(elf) => {
            for inst in elf.disassemble_address(address) {
                process_instruction(&inst);
            }
        }

        lief::Binary::PE(pe) => {
            for inst in pe.disassemble_address(address) {
                process_instruction(&inst);
            }
        }

        lief::Binary::MachO(fat) => {
            for macho in fat.iter() {
                for inst in macho.disassemble_address(address) {
                    process_instruction(&inst);
                }
            }
        }
    }
}

fn disa_from_symbol(name: &str, symbol: &str) {
    let bin = get_binary(name);

    match bin {
        lief::Binary::ELF(elf) => {
            for inst in elf.disassemble_symbol(symbol) {
                process_instruction(&inst);
            }
        }

        lief::Binary::PE(pe) => {
            for inst in pe.disassemble_symbol(symbol) {
                process_instruction(&inst);
            }
        }

        lief::Binary::MachO(fat) => {
            for macho in fat.iter() {
                for inst in macho.disassemble_symbol(symbol) {
                    process_instruction(&inst);
                }
            }
        }
    }
}

#[test]
fn test_from_slice() {
    if !lief::is_extended() {
        return;
    }

    if let lief::Binary::ELF(elf) = get_binary("ELF/hello.bpf.o") {
        let section = elf.section_by_name("tp/syscalls/sys_enter_write").unwrap();
        for inst in elf.disassemble_slice(section.content(), 0x100) {
            process_instruction(&inst);
        }
    }
}

#[test]
fn test_upx() {
    if !lief::is_extended() {
        return;
    }

    if let lief::Binary::PE(pe) = get_binary("PE/PE32_x86_binary_cmd-upx.exe") {
        let section = pe.section_by_name("UPX1").unwrap();
        let delta = 0x4ad4ee70 - 0x4ad3c000;
        for inst in pe.disassemble_slice(&section.content()[delta..], 0x4ad4ee70) {
            process_instruction(&inst);
        }
    }
}

#[test]
fn test_api() {
    if !lief::is_extended() {
        return;
    }

    disa_from_symbol("ELF/libmonochrome-armv7.so", "Java_J_N_MENF59pO");
    disa_from_address("MachO/MachO32_ARM_binary_data-in-code-LLVM.bin", 0);
    disa_from_address("ELF/echo.mips_r3000.bin", 0x00403664);
    disa_from_address("MachO/macho-issue-1110.bin", 0x00000b10);
    disa_from_address("ELF/i872_risv.elf", 0x80000000);
    disa_from_address("ELF/elf_reader.riscv32.elf", 0x0001e810);
    disa_from_address("PE/PE32_x86_binary_cmd-upx.exe", 0x0001e810);
    disa_from_address("PE/ntoskrnl.exe", 0x140200000);
    disa_from_address("ELF/ELF32_x86_library_libshellx.so", 0x000010c0);
    disa_from_address("ELF/ELF64_x86-64_binary_static-binary.bin", 0x00400cdd);
    disa_from_address("MachO/FAT_MachO_x86_x86-64_library_libdyld.dylib", 0x1141);
    disa_from_address("MachO/FAT_MachO_x86_x86-64_library_libdyld.dylib", 0x1108);
    disa_from_address("MachO/ios17/DebugHierarchyKit", 0x16650);
}
