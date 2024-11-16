#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Coarray.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Coarray>(nb::module_& m) {
  nb::class_<dw::types::Coarray, dw::Type> type(m, "Coarray",
    R"doc(
    This class represents the ``DW_TAG_coarray_type`` type
    )doc"_doc
  );
}

}
