#include "LIEF/DWARF/editor/StructType.hpp"

#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::editor::StructType>(nb::module_& m) {
  nb::class_<dw::editor::StructType, dw::editor::Type> S(m, "StructType",
    R"doc(
    This class represents a struct-like type which can be:

    - ``DW_TAG_class_type``
    - ``DW_TAG_structure_type``
    - ``DW_TAG_union_type``
    )doc"_doc
  );

  using TYPE = dw::editor::StructType::TYPE;
  nb::enum_<TYPE>(S, "TYPE")
    .value("CLASS", TYPE::CLASS, "Discriminant for ``DW_TAG_class_type``"_doc)
    .value("STRUCT", TYPE::STRUCT, "Discriminant for ``DW_TAG_structure_type``"_doc)
    .value("UNION", TYPE::UNION, "Discriminant for ``DW_TAG_union_type``"_doc);

  nb::class_<dw::editor::StructType::Member>(S, "Member",
    "This class represents a member of the struct-like"_doc
  );

  S
    .def("set_size", &dw::editor::StructType::set_size,
      R"doc(
      Define the overall size which is equivalent to the ``sizeof`` of the
      current type.

      This function defines the ``DW_AT_byte_size`` attribute
      )doc"_doc, "size"_a, nb::rv_policy::reference_internal)

    .def("add_member", &editor::StructType::add_member,
      "Adds a member to the current struct-like"_doc,
      "name"_a, "type"_a, "offset"_a = -1)

    .def("add_bitfield", &editor::StructType::add_bitfield,
      "Adds a member to the current struct-like"_doc,
      "name"_a, "type"_a, "bitsize"_a, "bitoffset"_a = -1)
  ;
}

}
