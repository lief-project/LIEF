#include "DWARF/init.hpp"
#include "DWARF/pyDwarf.hpp"

#include "LIEF/DWARF/DebugInfo.hpp"
#include "LIEF/DWARF/Variable.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::dwarf::py {
void init(nb::module_& m) {
  nb::module_ dwarf = m.def_submodule("dwarf");

  dwarf.def("load", &LIEF::dwarf::load,
    R"doc(
    Load the DWARF from the given path
    )doc"_doc, "path"_a
  );

  create<LIEF::dwarf::Scope>(dwarf);
  create<LIEF::dwarf::Type>(dwarf);
  create<LIEF::dwarf::Variable>(dwarf);
  create<LIEF::dwarf::Function>(dwarf);
  create<LIEF::dwarf::CompilationUnit>(dwarf);
  create<LIEF::dwarf::DebugInfo>(dwarf);
}
}
