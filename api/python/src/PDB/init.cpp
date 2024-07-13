#include "PDB/init.hpp"
#include "PDB/pyPDB.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

#include "LIEF/PDB/DebugInfo.hpp"
#include "LIEF/PDB/Type.hpp"

namespace LIEF::pdb::py {
void init(nb::module_& m) {
  nb::module_ pdb = m.def_submodule("pdb");

  pdb.def("load", &LIEF::pdb::load,
    R"doc(
    Load the PDB from the given path
    )doc"_doc, "path"_a
  );

  create<LIEF::pdb::Type>(pdb);
  create<LIEF::pdb::DebugInfo>(pdb);
  create<LIEF::pdb::PublicSymbol>(pdb);
  create<LIEF::pdb::CompilationUnit>(pdb);
  create<LIEF::pdb::Function>(pdb);
}
}
