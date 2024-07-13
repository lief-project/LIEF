#include "LIEF/PDB/types/BitField.hpp"
#include "PDB/pyPDB.hpp"

namespace LIEF::pdb::py {
template<>
void create<pdb::types::BitField>(nb::module_& m) {
  nb::class_<pdb::types::BitField, pdb::Type> type(m, "BitField",
    R"doc(
    This class represents a ``LF_BITFIELD`` PDB type
    )doc"_doc
  );
}

}
