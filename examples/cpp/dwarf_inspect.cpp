#include <LIEF/DWARF.hpp>
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
    std::cerr << "Usage: " << argv[0] << " <dwarf file>\n";
    return EXIT_FAILURE;
  }

  set_level(LEVEL::INFO);
  std::unique_ptr<LIEF::dwarf::DebugInfo> dbg = LIEF::dwarf::load(argv[1]);
  if (!dbg) {
    return EXIT_FAILURE;
  }
  for (std::unique_ptr<LIEF::dwarf::CompilationUnit> CU : dbg->compilation_units()) {
    log(LEVEL::INFO, "Producer: {}", CU->producer());
    for (std::unique_ptr<LIEF::dwarf::Function> func : CU->functions()) {
      log(LEVEL::INFO, "name={}, linkage={}, address={}",
          func->name(), func->linkage_name(), std::to_string(func->address().value_or(0)));
    }

    for (std::unique_ptr<LIEF::dwarf::Variable> var : CU->variables()) {
      log(LEVEL::INFO, "name={}, address={}", var->name(), std::to_string(var->address().value_or(0)));
    }

    for (std::unique_ptr<LIEF::dwarf::Type> ty : CU->types()) {
      log(LEVEL::INFO, "name={}, size={}", ty->name().value_or(""), std::to_string(ty->size().value_or(0)));
    }
  }

  dbg->find_function("_ZNSi4peekEv");
  dbg->find_function("std::basic_istream<char, std::char_traits<char> >::peek()");
  dbg->find_function(0x137a70);

  dbg->find_variable("_ZNSt12out_of_rangeC1EPKc");
  dbg->find_function("std::out_of_range::out_of_range(char const*)");
  dbg->find_function(0x2773a0);
  return EXIT_SUCCESS;
}
