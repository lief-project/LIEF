#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Coarray.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Coarray>(nb::module_& m) {
  nb::class_<dw::types::Coarray, dw::Type> type(
      m, "Coarray", "This class represents the ``DW_TAG_coarray_type`` type"_doc
  );
}

}
