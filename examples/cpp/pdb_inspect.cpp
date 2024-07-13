#include <LIEF/PE.hpp>
#include <LIEF/PDB.hpp>
#include <LIEF/logging.hpp>
#include <LIEF/utils.hpp>
#include <cstdlib>
#include <iostream>

using namespace LIEF::logging;

int main(int argc, const char** argv) {
  if (!LIEF::is_extended()) {
    std::cerr << "This example requires the extended version of LIEF\n";
    return EXIT_FAILURE;
  }

  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <pdb file>\n";
    return EXIT_FAILURE;
  }

  std::unique_ptr<LIEF::pdb::DebugInfo> pdb = LIEF::pdb::load(argv[1]);
  if (!pdb) {
    return EXIT_FAILURE;
  }
  set_level(LEVEL::INFO);

  log(LEVEL::INFO, "age={}, guid={}", std::to_string(pdb->age()), pdb->guid());

  for (std::unique_ptr<LIEF::pdb::PublicSymbol> symbol : pdb->public_symbols()) {
    log(LEVEL::INFO, "name={}, section={}, RVA={}",
        symbol->name(), symbol->section_name(), std::to_string(symbol->RVA()));
  }

  for (std::unique_ptr<LIEF::pdb::Type> ty : pdb->types()) {
    if (LIEF::pdb::types::Class::classof(ty.get())) {
      auto* clazz = ty->as<LIEF::pdb::types::Class>();
      log(LEVEL::INFO, "Class[name]={}", clazz->name());
    }
  }

  for (std::unique_ptr<LIEF::pdb::CompilationUnit> CU : pdb->compilation_units()) {
    log(LEVEL::INFO, "module={}", CU->module_name());
    for (const std::string& src : CU->sources()) {
      log(LEVEL::INFO, "  - {}", src);
    }

    for (std::unique_ptr<LIEF::pdb::Function> func : CU->functions()) {
      log(LEVEL::INFO, "name={}, section={}, RVA={}, code size={}",
          func->name(), func->section_name(), std::to_string(func->RVA()),
          std::to_string(func->code_size()));
    }
  }



  return EXIT_SUCCESS;
}
