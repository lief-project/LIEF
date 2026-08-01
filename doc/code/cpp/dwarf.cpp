#include <cassert>
#include <iostream>
#include <memory>
#include <string>

#include <LIEF/Abstract/Binary.hpp>
#include <LIEF/DWARF.hpp>
#include <LIEF/ELF.hpp>
#include <LIEF/PE.hpp>
#include <LIEF/asm/Instruction.hpp>
#include <LIEF/logging.hpp>

using namespace LIEF::logging;

void embedded() {
  // lief-doc: embedded-start
  auto elf = LIEF::ELF::Parser::parse("/bin/with_debug");
  if (const LIEF::DebugInfo* info = elf->debug_info()) {
    assert(LIEF::dwarf::DebugInfo::classof(info) && "Wrong debug type");

    const auto& dwarf_dbg = static_cast<const LIEF::dwarf::DebugInfo&>(*info);
  }
  // lief-doc: embedded-end
}

void load() {
  // lief-doc: load-start
  auto dbg = LIEF::dwarf::load("/bin/with_debug");
  dbg = LIEF::dwarf::load("external_dwarf");
  dbg = LIEF::dwarf::load("debug.dwo");
  // lief-doc: load-end
  (void)dbg;
}

void iterate() {
  // lief-doc: iterate-start
  std::unique_ptr<LIEF::dwarf::DebugInfo> dbg;

  for (const LIEF::dwarf::CompilationUnit& CU : dbg->compilation_units()) {
    log(LEVEL::INFO, "Producer: {}", CU.producer());
    for (const LIEF::dwarf::Function& func : CU.functions()) {
      log(LEVEL::INFO, "name={}, linkage={}, address={}", func.name(),
          func.linkage_name(), std::to_string(func.address().value_or(0)));
    }

    for (const LIEF::dwarf::Variable& var : CU.variables()) {
      log(LEVEL::INFO, "name={}, address={}", var.name(),
          std::to_string(var.address().value_or(0)));
    }

    for (const LIEF::dwarf::Type& ty : CU.types()) {
      log(LEVEL::INFO, "name={}, size={}", ty.name().value_or(""),
          std::to_string(ty.size().value_or(0)));
    }
  }

  dbg->find_function("_ZNSi4peekEv");
  dbg->find_function("std::basic_istream<char, std::char_traits<char> >::peek()");
  dbg->find_function(0x137a70);

  dbg->find_variable("_ZNSt12out_of_rangeC1EPKc");
  dbg->find_variable("std::out_of_range::out_of_range(char const*)");
  dbg->find_variable(0x2773a0);
  // lief-doc: iterate-end
}

void load_external() {
  // lief-doc: load-external-start
  std::unique_ptr<LIEF::Binary> binary;

  binary->load_debug_info("/home/romain/dev/LIEF/some.dwo");
  // lief-doc: load-external-end
}

void disassemble_external() {
  // lief-doc: disassemble-start
  std::unique_ptr<LIEF::Binary> binary;

  binary->load_debug_info("/home/romain/dev/LIEF/some.dwo");

  // The location (address/size) of `my_function` is defined in some.dwo
  for (const LIEF::assembly::Instruction& inst :
       binary->disassemble("my_function"))
  {
    std::cout << inst << '\n';
  }
  // lief-doc: disassemble-end
}

void to_decl() {
  // lief-doc: to-decl-start
  auto dbg = LIEF::dwarf::load("/bin/with_debug");

  std::unique_ptr<LIEF::dwarf::Function> func = dbg->find_function("main");
  std::cout << func->to_decl() << '\n';

  LIEF::DeclOpt opt;
  opt.is_cpp(true).indentation(4);

  for (const LIEF::dwarf::CompilationUnit& CU : dbg->compilation_units()) {
    std::cout << CU.to_decl(opt) << '\n';
  }
  // lief-doc: to-decl-end
}

void editor_from_binary() {
  // lief-doc: editor-from-binary-start
  std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse("demo.exe");

  std::unique_ptr<LIEF::dwarf::Editor> editor =
      LIEF::dwarf::Editor::from_binary(*pe);
  // lief-doc: editor-from-binary-end
  (void)editor;
}

void editor_create() {
  // lief-doc: editor-create-start
  std::unique_ptr<LIEF::dwarf::Editor> editor;

  std::unique_ptr<LIEF::dwarf::editor::CompilationUnit> unit =
      editor->create_compilation_unit();

  unit->set_producer("LIEF");

  std::unique_ptr<LIEF::dwarf::editor::Function> func =
      unit->create_function("hello");

  func->set_address(0x123);

  func->set_return_type(*unit->create_structure("my_struct_t")->pointer_to());

  std::unique_ptr<LIEF::dwarf::editor::Variable> var =
      func->create_stack_variable("local_var");

  var->set_stack_offset(8);
  editor->write("/tmp/out.debug");
  // lief-doc: editor-create-end
}
