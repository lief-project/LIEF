#include "LIEF/PDB/types/Method.hpp"
#include "PDB/pyPDB.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Method>(nb::module_& m) {
  nb::class_<pdb::types::Method> type(m, "Method",
    R"doc(
    This class represents a Method (``LF_ONEMETHOD``) that can be defined in
    ClassLike PDB type
    )doc"_doc
  );

  type
    .def_prop_ro("name", &pdb::types::Method::name,
      R"doc(
      Name of the method
      )doc"_doc
    )
  ;
}

}
