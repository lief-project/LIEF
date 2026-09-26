#include "LIEF/DWARF/editor/CompilationUnit.hpp"
#include "LIEF/DWARF/editor/Function.hpp"
#include "LIEF/DWARF/editor/Variable.hpp"
#include "LIEF/DWARF/editor/ArrayType.hpp"
#include "LIEF/DWARF/editor/TypeDef.hpp"
#include "LIEF/DWARF/editor/StructType.hpp"
#include "LIEF/DWARF/editor/EnumType.hpp"
#include "LIEF/DWARF/editor/PointerType.hpp"
#include "LIEF/DWARF/editor/Type.hpp"

#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::editor::CompilationUnit>(nb::module_& m) {
  nb::class_<dw::editor::CompilationUnit> CU(m, "CompilationUnit",
    R"doc(
    This class represents an **editable** DWARF compilation unit
    )doc"_doc
  );

  CU
    .def("set_producer", &dw::editor::CompilationUnit::set_producer,
      R"doc(
      Set the ``DW_AT_producer`` producer attribute.

      This attribute aims to inform about the program that generated this
      compilation unit (e.g. ``LIEF Extended``)
      )doc"_doc, nb::rv_policy::reference_internal)

    .def("create_function", &dw::editor::CompilationUnit::create_function,
         "Create a new function owned by this compilation unit"_doc,
         "name"_a, nb::keep_alive<0, 1>())

    .def("create_variable", &dw::editor::CompilationUnit::create_variable,
         "Create a new **global** variable owned by this compilation unit"_doc,
         "name"_a, nb::keep_alive<0, 1>())

    .def("create_generic_type", &dw::editor::CompilationUnit::create_generic_type,
         "Create a ``DW_TAG_unspecified_type`` type with the given name"_doc,
         "name"_a, nb::keep_alive<0, 1>())

    .def("create_enum", &dw::editor::CompilationUnit::create_enum,
         "Create an enum type (``DW_TAG_enumeration_type``)"_doc,
         "name"_a, nb::keep_alive<0, 1>())

    .def("create_typedef", &dw::editor::CompilationUnit::create_typedef,
      R"doc(
      Create a typedef with the name provided in the first parameter which aliases
      the type provided in the second parameter
      )doc"_doc, "name"_a, "ty"_a, nb::keep_alive<0, 1>())

    .def("create_structure", &dw::editor::CompilationUnit::create_structure,
      "Create a struct-like type (struct, class, union) with the given name"_doc,
       "name"_a, "kind"_a = dw::editor::StructType::TYPE::STRUCT, nb::keep_alive<0, 1>())

    .def("create_base_type", &dw::editor::CompilationUnit::create_base_type,
      "Create a primitive type with the given name and size."_doc,
       "name"_a, "size"_a, "encoding"_a = dw::editor::BaseType::ENCODING::NONE, nb::keep_alive<0, 1>())

    .def("create_function_type", &dw::editor::CompilationUnit::create_function_type,
      "Create a function type with the given name."_doc, "name"_a, nb::keep_alive<0, 1>())

    .def("create_pointer_type", &dw::editor::CompilationUnit::create_pointer_type,
      "Create a pointer on the provided type."_doc, "ty"_a, nb::keep_alive<0, 1>())

    .def("create_const_type", &dw::editor::CompilationUnit::create_const_type,
      R"doc(
      Create a ``const``-qualified version of the provided type
      (``DW_TAG_const_type``).

      Qualifying the same type twice returns the same underlying DWARF entry.
      )doc"_doc, "ty"_a, nb::keep_alive<0, 1>())

    .def("create_volatile_type", &dw::editor::CompilationUnit::create_volatile_type,
      R"doc(
      Create a ``volatile``-qualified version of the provided type
      (``DW_TAG_volatile_type``).

      Qualifying the same type twice returns the same underlying DWARF entry.
      )doc"_doc, "ty"_a, nb::keep_alive<0, 1>())

    .def("create_void_type", &dw::editor::CompilationUnit::create_void_type,
      "Create a ``void`` type"_doc, nb::keep_alive<0, 1>())

    .def("create_array", &dw::editor::CompilationUnit::create_array,
      "Create an array type with the given name, type and size."_doc,
      "name"_a, "ty"_a, "count"_a, nb::keep_alive<0, 1>())
  ;
}

}
