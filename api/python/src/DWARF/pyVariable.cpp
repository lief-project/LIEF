#include "LIEF/DWARF/Variable.hpp"
#include "LIEF/DWARF/Scope.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "DWARF/pyDwarf.hpp"
#include "pyErr.hpp"
#include "DWARF/pyTypes.hpp"


#include <nanobind/make_iterator.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::Variable>(nb::module_& m) {
  nb::class_<dw::Variable> var(m, "Variable",
    R"doc(
    This class represents a DWARF variable which can be owned by a
    :class:`~.Function` or a :class:`~.CompilationUnit`.
    )doc"_doc
  );

  var
    .def_prop_ro("name", &dw::Variable::name,
      R"doc(
      Name of the variable (usually demangled)
      )doc"_doc
    )
    .def_prop_ro("linkage_name", &dw::Variable::linkage_name,
      R"doc(
      The name of the variable which is used for linking (``DW_AT_linkage_name``).

      This name differs from :attr:`~.name` as it is usually mangled. The function
      return an empty string if the linkage name is not available.
      )doc"_doc
    )
    .def_prop_ro("address",
      [] (const dw::Variable& self) {
          return LIEF::py::value_or_none(&dw::Variable::address, self);
      },
      R"doc(
      Address of the variable.

      If the variable is **static**, it returns the **virtual address**
      where it is defined.
      If the variable is stack-based, it returns the **relative offset** from
      the frame-base register.

      If the address can't be resolved, it returns ``None``.
      )doc"_doc
    )
    .def_prop_ro("size",
      [] (const dw::Variable& self) {
          return LIEF::py::value_or_none(&dw::Variable::size, self);
      },
      R"doc(
      Return the size of the variable (or a lief_errors if it can't be
      resolved).

      This size is defined by the type of the variable.
      )doc"_doc
    )
    .def_prop_ro("is_constexpr",
      &dw::Variable::is_constexpr,
      R"doc(
      Whether it's a ``constexpr`` variable.
      )doc"_doc
    )
    .def_prop_ro("debug_location",
      &dw::Variable::debug_location,
      R"doc(
      The original source location where the variable is defined.
      )doc"_doc
    )
    .def_prop_ro("type", &dw::Variable::type,
      R"doc(
      Return the type of this variable.
      )doc"_doc
    )
    .def_prop_ro("scope", &dw::Variable::scope,
      R"doc(
      Scope in which this variable is defined
      )doc"_doc
    )
  ;
}

}
