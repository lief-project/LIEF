#include "LIEF/DWARF/Scope.hpp"
#include "DWARF/pyDwarf.hpp"
#include "pyErr.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::Scope>(nb::module_& m) {
  nb::class_<dw::Scope> scope(m, "Scope",
    R"doc(
    This class materializes a scope in which :class:`~.dwarf.Function`,
    :class:`~.dwarf.Variable`, :class:`~.dwarf.Type`, ... can be defined.
    )doc"_doc
  );

  nb::enum_<dw::Scope::TYPE>(scope, "TYPE")
    .value("UNKNOWN", dw::Scope::TYPE::UNKNOWN)
    .value("UNION", dw::Scope::TYPE::UNION)
    .value("CLASS", dw::Scope::TYPE::CLASS)
    .value("STRUCT", dw::Scope::TYPE::STRUCT)
    .value("NAMESPACE", dw::Scope::TYPE::NAMESPACE)
    .value("FUNCTION", dw::Scope::TYPE::FUNCTION)
    .value("COMPILATION_UNIT", dw::Scope::TYPE::COMPILATION_UNIT)
  ;

  scope
    .def_prop_ro("name", &dw::Scope::name,
      R"doc(
      Name of the scope. For instance namespace's name or function's name.
      )doc"_doc
    )

    .def_prop_ro("parent", &dw::Scope::parent,
      R"doc(
      Parent scope (if any).
      )doc"_doc
    )

    .def_prop_ro("type", &dw::Scope::type,
      R"doc(
      The current scope type.
      )doc"_doc
    )

    .def("chained", &dw::Scope::chained,
      R"doc(
      Represent the whole chain of all (parent) scopes using the provided
      separator. E.g. ``ns1::ns2::Class1::Struct2::Type``.
      )doc"_doc, "sep"_a = "::"
    )
  ;
}
}
