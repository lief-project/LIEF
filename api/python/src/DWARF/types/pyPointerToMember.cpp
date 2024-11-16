#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/PointerToMember.hpp"
#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::types::PointerToMember>(nb::module_& m) {
  nb::class_<dw::types::PointerToMember, dw::Type> type(m, "PointerToMember",
    R"doc(
    This class represents the ``DW_TAG_ptr_to_member_type`` type
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &dw::types::PointerToMember::underlying_type,
      R"doc(
      The type of the member referenced by this pointer.
      )doc"_doc
    )
    .def_prop_ro("containing_type", &dw::types::PointerToMember::containing_type,
      R"doc(
      The type that embeds this member.
      )doc"_doc
    )
  ;
}

}
