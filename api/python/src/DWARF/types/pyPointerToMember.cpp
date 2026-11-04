#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/PointerToMember.hpp"

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::types::PointerToMember>(nb::module_& m) {
  nb::class_<dw::types::PointerToMember, dw::Type> type(
      m, "PointerToMember",
      "This class represents the ``DW_TAG_ptr_to_member_type`` type"_doc
  );

  type.def_prop_ro("underlying_type", &dw::types::PointerToMember::underlying_type,
                   "The type of the member referenced by this pointer."_doc,
                   nb::keep_alive<0, 1>())
      .def_prop_ro("containing_type", &dw::types::PointerToMember::containing_type,
                   "The type that embeds this member."_doc,
                   nb::keep_alive<0, 1>());
}

}
