#include <LIEF/DWARF.hpp>
#include <LIEF/logging.hpp>
#include <LIEF/PE.hpp>
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
    std::cerr << "Usage: " << argv[0] << " <pe>\n";
    return EXIT_FAILURE;
  }

  std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse(argv[1]);
  std::unique_ptr<LIEF::dwarf::Editor> editor = LIEF::dwarf::Editor::from_binary(*pe);

  std::unique_ptr<LIEF::dwarf::editor::CompilationUnit> unit = editor->create_compilation_unit();
  unit->set_producer("LIEF");

  std::unique_ptr<LIEF::dwarf::editor::Function> func = unit->create_function("hello");
  func->set_address(0x123);

  func->set_return_type(
    *unit->create_structure("my_struct_t")->pointer_to()
  );

  std::unique_ptr<LIEF::dwarf::editor::Variable> var =
    func->create_stack_variable("local_var");

  var->set_stack_offset(8);
  editor->write("/tmp/out.debug");
  return EXIT_SUCCESS;
}
