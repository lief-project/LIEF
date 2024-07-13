#include "LIEF/PDB/types/Function.hpp"
#include "PDB/pyPDB.hpp"

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Function>(nb::module_& m) {
  nb::class_<pdb::types::Function, pdb::Type> type(m, "Function",
    R"doc(
    This class represents a ``LF_PROCEDURE`` PDB type
    )doc"_doc
  );
}

}
