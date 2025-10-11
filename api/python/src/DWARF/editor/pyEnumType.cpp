#include "LIEF/DWARF/editor/EnumType.hpp"

#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::editor::EnumType>(nb::module_& m) {
  nb::class_<dw::editor::EnumType, dw::editor::Type> E(m, "EnumType",
    R"doc(
    This class represents an editable enum type (``DW_TAG_enumeration_type``)
    )doc"_doc
  );

  nb::class_<dw::editor::EnumType::Value>(E, "Value",
    "This class represents an enum value"_doc
  );

  E
    .def("set_size", &dw::editor::EnumType::set_size,
      R"doc(
      Define the number of bytes required to hold an instance of the
      enumeration (``DW_AT_byte_size``).
      )doc"_doc, "size"_a, nb::rv_policy::reference_internal)

    .def("set_underlying_type", &dw::editor::EnumType::set_underlying_type,
      "Set the underlying type that is used to encode this enum"_doc,
      "type"_a, nb::rv_policy::reference_internal
    )

    .def("add_value", &dw::editor::EnumType::add_value,
      R"doc(
      Add an enum value by specifying its name and its integer value.
      )doc"_doc, "name"_a, "value"_a, nb::rv_policy::reference_internal)
  ;
}

}
