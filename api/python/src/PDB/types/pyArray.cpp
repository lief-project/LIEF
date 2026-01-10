#include "LIEF/PDB/types/Array.hpp"
#include "PDB/pyPDB.hpp"

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Array>(nb::module_& m) {
  using Array = pdb::types::Array;
  nb::class_<pdb::types::Array, pdb::Type> type(m, "Array",
    R"doc(
    This class represents a ``LF_ARRAY`` PDB type.
    )doc"_doc
  );

  type
    .def_prop_ro("numberof_elements", &Array::numberof_elements,
      "Number of elements in this array"_doc
    )

    .def_prop_ro("element_type", &Array::element_type,
      "Type of the elements"_doc
    )

    .def_prop_ro("index_type", &Array::index_type,
      "Type of the index"_doc
    )
  ;
}

}
