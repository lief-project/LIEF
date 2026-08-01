#include <cassert>
#include <iostream>
#include <memory>
#include <string>

#include <LIEF/Abstract/Binary.hpp>
#include <LIEF/Abstract/DebugInfo.hpp>
#include <LIEF/DebugDeclOpt.hpp>
#include <LIEF/PDB.hpp>
#include <LIEF/PE.hpp>
#include <LIEF/asm/Instruction.hpp>
#include <LIEF/logging.hpp>

using namespace LIEF::logging;

void load_pdb() {
  // lief-doc: load-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  if (const LIEF::DebugInfo* info = pe->debug_info()) {
    assert(LIEF::pdb::DebugInfo::classof(info) && "Wrong DebugInfo type");
    const auto& pdb = static_cast<const LIEF::pdb::DebugInfo&>(*info);
  }

  // Or loading directly the pdb file
  std::unique_ptr<LIEF::pdb::DebugInfo> pdb = LIEF::pdb::load("some.pdb");
  // lief-doc: load-end
  (void)pdb;
}

void load_ext() {
  // lief-doc: load-ext-start
  std::unique_ptr<LIEF::Binary> binary;

  binary->load_debug_info(R"(C:\Users\romain\LIEF.pdb)");
  // lief-doc: load-ext-end
}

void disassemble() {
  // lief-doc: disassemble-start
  std::unique_ptr<LIEF::Binary> binary;

  binary->load_debug_info(R"(C:\Users\romain\LIEF.pdb)");

  // The location (address/size) of `my_function` is defined in LIEF.pdb
  for (const LIEF::assembly::Instruction& inst :
       binary->disassemble("my_function"))
  {
    std::cout << inst << '\n';
  }
  // lief-doc: disassemble-end
}

void to_decl() {
  // lief-doc: to-decl-start
  std::unique_ptr<LIEF::pdb::DebugInfo> pdb;

  LIEF::DeclOpt opt;
  opt.is_cpp(true);

  for (const LIEF::pdb::Type& ty : pdb->types()) {
    std::cout << ty.to_decl(opt) << '\n';
  }

  for (const LIEF::pdb::CompilationUnit& CU : pdb->compilation_units()) {
    std::cout << CU.to_decl(opt) << '\n';
    for (const LIEF::pdb::Function& func : CU.functions()) {
      std::cout << func.to_decl(opt) << '\n';
    }
  }
  // lief-doc: to-decl-end
}

void explore() {
  // lief-doc: explore-start
  std::unique_ptr<LIEF::pdb::DebugInfo> pdb;
  log(Level::Info, "age={}, guid={}", std::to_string(pdb->age()), pdb->guid());

  for (const LIEF::pdb::PublicSymbol& symbol : pdb->public_symbols()) {
    log(Level::Info, "name={}, section={}, RVA={}", symbol.name(),
        symbol.section_name(), std::to_string(symbol.RVA()));
  }

  for (const LIEF::pdb::Type& ty : pdb->types()) {
    if (LIEF::pdb::types::Class::classof(&ty)) {
      const auto* clazz = ty.as<LIEF::pdb::types::Class>();
      log(Level::Info, "Class[name]={}", clazz->name().value_or(""));
    }
  }

  for (const LIEF::pdb::CompilationUnit& CU : pdb->compilation_units()) {
    log(Level::Info, "module={}", CU.module_name());
    for (const std::string& src : CU.sources()) {
      log(Level::Info, "  - {}", src);
    }

    for (const LIEF::pdb::Function& func : CU.functions()) {
      log(Level::Info, "name={}, section={}, RVA={}, code size={}", func.name(),
          func.section_name(), std::to_string(func.RVA()),
          std::to_string(func.code_size()));
    }
  }
  // lief-doc: explore-end
}
