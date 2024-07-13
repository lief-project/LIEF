#include "LIEF/PDB/types/Pointer.hpp"
#include "PDB/pyPDB.hpp"
#include "PDB/pyType.hpp"

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Pointer>(nb::module_& m) {
  nb::class_<pdb::types::Pointer, pdb::Type> type(m, "Pointer",
    R"doc(
    This class represents a ``LF_POINTER`` PDB type
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &pdb::types::Pointer::underlying_type,
      R"doc(
      The underlying type pointed by this pointer
      )doc"_doc
    )
  ;
}

}
