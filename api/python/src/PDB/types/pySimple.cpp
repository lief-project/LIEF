#include "LIEF/PDB/types/Simple.hpp"
#include "PDB/pyPDB.hpp"

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Simple>(nb::module_& m) {
  nb::class_<pdb::types::Simple, pdb::Type> type(m, "Simple",
    R"doc(
    This class represents a primitive types (int, float, ...) which are
    also named *simple* types in the PDB format.
    )doc"_doc
  );
}

}
