#include "LIEF/DWARF/Editor.hpp"
#include "LIEF/DWARF/editor/CompilationUnit.hpp"
#include "LIEF/Abstract/Binary.hpp"

#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>
#include "nanobind/extra/stl/pathlike.h"

namespace LIEF::dwarf::py {
template<>
void create<dw::Editor>(nb::module_& m) {
  nb::module_ m_editor = m.def_submodule("editor");

  create<LIEF::dwarf::editor::Type>(m_editor);
  create<LIEF::dwarf::editor::Function>(m_editor);
  create<LIEF::dwarf::editor::Variable>(m_editor);
  create<LIEF::dwarf::editor::CompilationUnit>(m_editor);

  nb::class_<dw::Editor> editor(m, "Editor",
    R"doc(
    This class exposes the main API to create DWARF information
    )doc"_doc
  );

  nb::enum_<dw::Editor::ARCH>(editor, "ARCH")
    .value("X64", dw::Editor::ARCH::X64)
    .value("X86", dw::Editor::ARCH::X86)
    .value("AARCH64", dw::Editor::ARCH::AARCH64)
    .value("ARM", dw::Editor::ARCH::ARM)
  ;

  nb::enum_<dw::Editor::FORMAT>(editor, "FORMAT")
    .value("ELF", dw::Editor::FORMAT::ELF)
    .value("PE", dw::Editor::FORMAT::PE)
    .value("MACHO", dw::Editor::FORMAT::MACHO)
  ;

  editor
    .def_static("from_binary", &dw::Editor::from_binary,
      "Instantiate an editor for the given binary object"_doc,
      "bin"_a
    )
    .def_static("create", &dw::Editor::create,
      "Instantiate an editor for the given format and arch"_doc,
      "fmt"_a, "arch"_a
    )
    .def("create_compilation_unit", &dw::Editor::create_compilation_unit,
      "Create a new compilation unit"_doc
    )
    .def("write", [] (dw::Editor& self, nb::PathLike path) {
        self.write(path);
      },
      "Write the DWARF file to the specified output"_doc,
      "output"_a
    )
  ;

}

}
