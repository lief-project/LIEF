#include "DWARF/init.hpp"
#include "DWARF/pyDwarf.hpp"

#include "LIEF/DWARF/DebugInfo.hpp"
#include "LIEF/DWARF/Variable.hpp"
#include "LIEF/DWARF/Editor.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>
#include "nanobind/extra/stl/pathlike.h"

namespace LIEF::dwarf::py {
void init(nb::module_& m) {
  nb::module_ dwarf = m.def_submodule("dwarf");

  dwarf.def("load", [] (nb::PathLike path) { return load(path); },
    R"doc(
    Load the DWARF from the given path
    )doc"_doc, "path"_a
  );

  create<LIEF::dwarf::Scope>(dwarf);
  create<LIEF::dwarf::Type>(dwarf);
  create<LIEF::dwarf::Variable>(dwarf);
  create<LIEF::dwarf::Function>(dwarf);
  create<LIEF::dwarf::Parameter>(dwarf);
  create<LIEF::dwarf::CompilationUnit>(dwarf);
  create<LIEF::dwarf::DebugInfo>(dwarf);
  create<LIEF::dwarf::Editor>(dwarf);
  create<LIEF::dwarf::LexicalBlock>(dwarf);
}
}
