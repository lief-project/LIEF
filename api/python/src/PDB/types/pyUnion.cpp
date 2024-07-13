#include "LIEF/PDB/types/Union.hpp"
#include "PDB/pyPDB.hpp"

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Union>(nb::module_& m) {
  nb::class_<pdb::types::Union, pdb::types::ClassLike> type(m, "Union",
    R"doc(
    This class represents a ``LF_UNION`` PDB type
    )doc"_doc
  );
}

}
