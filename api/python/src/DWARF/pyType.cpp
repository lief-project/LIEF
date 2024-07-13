#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/Scope.hpp"
#include "DWARF/pyDwarf.hpp"
#include "pyErr.hpp"

#include "DWARF/pyTypes.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::dwarf::types {
class ClassLike;
class Pointer;
class Const;
class Base;
class Array;
}

namespace LIEF::dwarf::py {
template<>
void create<dw::Type>(nb::module_& m) {
  nb::module_ types = m.def_submodule("types", "DWARF Types"_doc);

  nb::class_<dw::Type> type(m, "Type",
    R"doc(
    This class represents a DWARF Type which includes:

    - ``DW_TAG_array_type``
    - ``DW_TAG_const_type``
    - ``DW_TAG_pointer_type``
    - ``DW_TAG_structure_type``
    - ``DW_TAG_base_type``
    - ``DW_TAG_class_type``
    - ``DW_TAG_enumeration_type``
    - ``DW_TAG_string_type``
    - ``DW_TAG_union_type``
    - ``DW_TAG_volatile_type``
    - ``DW_TAG_unspecified_type``
    )doc"_doc
  );

  nb::enum_<Type::KIND>(type, "KIND")
    .value("UNKNOWN", Type::KIND::UNKNOWN)
    .value("UNSPECIFIED", Type::KIND::UNSPECIFIED)
    .value("BASE", Type::KIND::BASE)
    .value("CONST", Type::KIND::CONST)
    .value("CLASS", Type::KIND::CLASS)
    .value("ARRAY", Type::KIND::ARRAY)
    .value("POINTER", Type::KIND::POINTER)
    .value("STRUCT", Type::KIND::STRUCT)
    .value("UNION", Type::KIND::UNION)
  ;
  type
    .def_prop_ro("kind", &dw::Type::kind,
        R"doc(
        Discriminator for the type's subclasses
        )doc"_doc
    )
    .def_prop_ro("name",
        [] (const dw::Type& self) {
          return LIEF::py::value_or_none(&dw::Type::name, self);
        },
        R"doc(
        Return the type's name or ``None`` if it can't be resolved.
        )doc"_doc
    )

    .def_prop_ro("size",
        [] (const dw::Type& self) {
          return LIEF::py::value_or_none(&dw::Type::size, self);
        },
        R"doc(
        Return the size of the type or ``None`` if it can't be computed.

        This size should match the equivalent of ``sizeof(Type)``.
        )doc"_doc
    )

    .def_prop_ro("location", &dw::Type::location,
      R"doc(
      Return the debug location where this type is defined.
      )doc"_doc
    )

    .def_prop_ro("is_unspecified", &dw::Type::is_unspecified,
      R"doc(
      Whether this type is a ``DW_TAG_unspecified_type``
      )doc"_doc
    )

    .def_prop_ro("scope", &dw::Type::scope,
      R"doc(
      Scope in which this type is defined
      )doc"_doc
    )
  ;

  create<dw::types::ClassLike>(types);
  create<dw::types::Pointer>(types);
  create<dw::types::Const>(types);
  create<dw::types::Base>(types);
  create<dw::types::Array>(types);
}

}
