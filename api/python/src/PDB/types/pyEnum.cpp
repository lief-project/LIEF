#include "LIEF/PDB/types/Enum.hpp"
#include "PDB/pyPDB.hpp"

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Enum>(nb::module_& m) {
  nb::class_<pdb::types::Enum, pdb::Type> type(m, "Enum",
    R"doc(
    This class represents a ``LF_ENUM`` PDB type
    )doc"_doc
  );
}

}
