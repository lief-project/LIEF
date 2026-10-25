#include "LIEF/PDB/types/Modifier.hpp"
#include "PDB/pyPDB.hpp"
#include "PDB/pyType.hpp"

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Modifier>(nb::module_& m) {
  nb::class_<pdb::types::Modifier, pdb::Type> type(
      m, "Modifier", "This class represents a ``LF_MODIFIER`` PDB type"_doc
  );

  type.def_prop_ro("underlying_type", &pdb::types::Modifier::underlying_type,
                   "Underlying type targeted by this modifier"_doc,
                   nb::keep_alive<0, 1>());
}

}
