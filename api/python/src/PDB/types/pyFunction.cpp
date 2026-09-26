#include "LIEF/PDB/types/Function.hpp"
#include "PDB/pyPDB.hpp"
#include "pyutils.hpp"

#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Function>(nb::module_& m) {
  using Function = pdb::types::Function;
  nb::class_<Function, pdb::Type> type(m, "Function",
    R"doc(
    This class represents a ``LF_PROCEDURE`` PDB type
    )doc"_doc
  );

  type
    .def_prop_ro("return_type", &Function::return_type,
      "Type returned by this function"_doc, nb::keep_alive<0, 1>()
    )

    .def_prop_ro("parameters", &Function::parameters,
      "Types of the function's parameters"_doc,
      nb::call_policy<LIEF::py::returns_references_to<1>>()
    );
}

}
