#include <iostream>
#include <memory>
#include <string>

#include <LIEF/DWARF.hpp>
#include <LIEF/DyldSharedCache.hpp>
#include <LIEF/ELF.hpp>
#include <LIEF/PE.hpp>
#include <LIEF/asm/Instruction.hpp>
#include <LIEF/asm/riscv/Instruction.hpp>
#include <LIEF/asm/x86/Instruction.hpp>

void disassemble() {
  // lief-doc: disassemble-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  for (const auto& inst : pe->disassemble("_WinRT")) {
    std::cout << inst.to_string() << '\n';
  }
  // lief-doc: disassemble-end
}

void check_opcode() {
  // lief-doc: downcast-start
  std::unique_ptr<LIEF::assembly::Instruction> inst;

  if (const auto* riscv_inst = inst->as<LIEF::assembly::riscv::Instruction>()) {
    LIEF::assembly::riscv::OPCODE opcode = riscv_inst->opcode();
  }
  // lief-doc: downcast-end
}

void dsc_disassemble() {
  // lief-doc: dsc-disassemble-start
  std::unique_ptr<LIEF::dsc::DyldSharedCache> dyld_cache;

  for (const auto& inst : dyld_cache->disassemble(0x1886f4a44)) {
    std::cout << inst.to_string() << '\n';
  }
  // lief-doc: dsc-disassemble-end
}

void dwarf_function() {
  // lief-doc: dwarf-func-start
  auto elf = LIEF::ELF::Parser::parse("/bin/hello");

  if (const auto* dwarf = elf->debug_info()->as<LIEF::dwarf::DebugInfo>()) {
    std::unique_ptr<LIEF::dwarf::Function> _main = dwarf->find_function("main");
    for (const auto& inst : _main->instructions()) {
      std::cout << inst.to_string() << '\n';
    }
  }
  // lief-doc: dwarf-func-end
}

void x86_lock() {
  // lief-doc: x86-lock-start
  std::unique_ptr<LIEF::assembly::x86::Instruction> inst;

  if (inst->has_lock_prefix() || inst->is_atomic()) {
    std::cout << inst->to_string() << " is atomic\n";
  } else if (inst->is_lockable()) {
    if (auto locked = inst->lock()) {
      std::cout << "atomic version: " << locked->to_string() << '\n';
    }
  }
  // lief-doc: x86-lock-end
}
