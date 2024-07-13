#include "LIEF/PDB/types/Array.hpp"
#include "PDB/pyPDB.hpp"

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Array>(nb::module_& m) {
  nb::class_<pdb::types::Array, pdb::Type> type(m, "Array",
    R"doc(
    This class represents a ``LF_ARRAY`` PDB type.
    )doc"_doc
  );
}

}
