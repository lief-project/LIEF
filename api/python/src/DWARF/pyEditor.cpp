#include "LIEF/DWARF/Editor.hpp"
#include "LIEF/DWARF/editor/CompilationUnit.hpp"
#include "LIEF/Abstract/Binary.hpp"

#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

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

  editor
    .def_static("from_binary", &dw::Editor::from_binary,
      "Instantiate an editor for the given binary object"_doc,
      "bin"_a
    )
    .def("create_compilation_unit", &dw::Editor::create_compilation_unit,
      "Create a new compilation unit"_doc
    )
    .def("write", &dw::Editor::write,
      "Write the DWARF file to the specified output"_doc,
      "output"_a
    )
  ;

}

}
