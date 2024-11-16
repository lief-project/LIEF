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
class Typedef;
class Atomic;
class Coarray;
class Dynamic;
class Enum;
class File;
class Immutable;
class Interface;
class PointerToMember;
class RValueReference;
class Reference;
class Restrict;
class SetTy;
class Shared;
class StringTy;
class Subroutine;
class TemplateAlias;
class Thrown;
class Volatile;
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
    - ``DW_TAG_typedef``
    - ``DW_TAG_reference_type``
    - ``DW_TAG_subroutine_type``
    - ``DW_TAG_ptr_to_member_type``
    - ``DW_TAG_set_type``
    - ``DW_TAG_packed_type``
    - ``DW_TAG_file_type``
    - ``DW_TAG_thrown_type``
    - ``DW_TAG_restrict_type``
    - ``DW_TAG_interface_type``
    - ``DW_TAG_shared_type``
    - ``DW_TAG_rvalue_reference_type``
    - ``DW_TAG_template_alias``
    - ``DW_TAG_coarray_type``
    - ``DW_TAG_dynamic_type``
    - ``DW_TAG_atomic_type``
    - ``DW_TAG_immutable_type``

    )doc"_doc
  );

  nb::enum_<Type::KIND>(type, "KIND")
    .value("UNKNOWN", Type::KIND::UNKNOWN)
    .value("UNSPECIFIED", Type::KIND::UNSPECIFIED)
    .value("BASE", Type::KIND::BASE)
    .value("CONST_KIND", Type::KIND::CONST_KIND)
    .value("CLASS", Type::KIND::CLASS)
    .value("ARRAY", Type::KIND::ARRAY)
    .value("POINTER", Type::KIND::POINTER)
    .value("STRUCT", Type::KIND::STRUCT)
    .value("UNION", Type::KIND::UNION)
    .value("TYPEDEF", Type::KIND::TYPEDEF)
    .value("REF", Type::KIND::REF)
    .value("SET_TYPE", Type::KIND::SET_TYPE)
    .value("STRING", Type::KIND::STRING)
    .value("SUBROUTINE", Type::KIND::SUBROUTINE)
    .value("POINTER_MEMBER", Type::KIND::POINTER_MEMBER)
    .value("PACKED", Type::KIND::PACKED)
    .value("FILE", Type::KIND::FILE)
    .value("THROWN", Type::KIND::THROWN)
    .value("VOLATILE", Type::KIND::VOLATILE)
    .value("RESTRICT", Type::KIND::RESTRICT)
    .value("INTERFACE", Type::KIND::INTERFACE)
    .value("SHARED", Type::KIND::SHARED)
    .value("RVALREF", Type::KIND::RVALREF)
    .value("TEMPLATE_ALIAS", Type::KIND::TEMPLATE_ALIAS)
    .value("COARRAY", Type::KIND::COARRAY)
    .value("DYNAMIC", Type::KIND::DYNAMIC)
    .value("ATOMIC", Type::KIND::ATOMIC)
    .value("IMMUTABLE", Type::KIND::IMMUTABLE)
    .value("ENUM", Type::KIND::ENUM)
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

        The name is resolved using either ``DW_AT_name`` or ``DW_AT_picture_string``.
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
  create<dw::types::Typedef>(types);
  create<dw::types::Atomic>(types);
  create<dw::types::Coarray>(types);
  create<dw::types::Dynamic>(types);
  create<dw::types::Enum>(types);
  create<dw::types::File>(types);
  create<dw::types::Immutable>(types);
  create<dw::types::Interface>(types);
  create<dw::types::PointerToMember>(types);
  create<dw::types::RValueReference>(types);
  create<dw::types::Reference>(types);
  create<dw::types::Restrict>(types);
  create<dw::types::SetTy>(types);
  create<dw::types::Shared>(types);
  create<dw::types::StringTy>(types);
  create<dw::types::Subroutine>(types);
  create<dw::types::TemplateAlias>(types);
  create<dw::types::Thrown>(types);
  create<dw::types::Volatile>(types);
}

}
