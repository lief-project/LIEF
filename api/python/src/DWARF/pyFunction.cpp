#include "LIEF/DWARF/DebugInfo.hpp"
#include "LIEF/DWARF/Function.hpp"
#include "LIEF/DWARF/Scope.hpp"
#include "LIEF/DWARF/Variable.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "DWARF/pyDwarf.hpp"
#include "pyErr.hpp"

#include <nanobind/make_iterator.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/string.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::Function>(nb::module_& m) {
  nb::class_<dw::Function> func(m, "Function",
    R"doc(
    This class represents a DWARF function which can be associated with either:
    ``DW_TAG_subprogram`` or ``DW_TAG_inlined_subroutine``.
    )doc"_doc
  );

  nb::class_<dw::Function::Parameter> param(func, "Parameter",
    R"doc(
    This class represents a DWARF function's parameter.
    )doc"_doc
  );

  param
    .def_prop_ro("name", &Function::Parameter::name,
      R"doc(
      The name of the parameter
      )doc"_doc
    )

    .def_prop_ro("type", &Function::Parameter::type,
      R"doc(
      Type of the parameter
      )doc"_doc
    )
  ;

  func
    .def_prop_ro("name", &dw::Function::name,
      R"doc(
      The name of the function (``DW_AT_name``)
      )doc"_doc
    )

    .def_prop_ro("linkage_name", &dw::Function::linkage_name,
      R"doc(
      The name of the function which is used for linking (`DW_AT_linkage_name`).

      This name differs from :attr:`~.name` as it is usually mangled. The function
      return an empty string if the linkage name is not available.
      )doc"_doc
    )

    .def_prop_ro("address",
      [] (const dw::Function& self) {
          return LIEF::py::value_or_none(&dw::Function::address, self);
      },
      R"doc(
      Return the address of the function (``DW_AT_entry_pc`` or ``DW_AT_low_pc``) or
      ``None`` if it's not available.
      )doc"_doc
    )

    .def_prop_ro("variables",
        [] (dw::Function& self) {
          auto vars = self.variables();
          return nb::make_iterator(
              nb::type<dw::Function>(), "variables_it", vars);
        }, nb::keep_alive<0, 1>(),
        R"delim(
        Return an iterator over the variables (``DW_TAG_variable``) defined within the
        scope of this function. This includes regular stack-based variables as
        well as static ones.
        )delim"_doc
    )

    .def_prop_ro("is_artificial", &dw::Function::is_artificial,
      R"doc(
      Whether this function is created by the compiler and not
      present in the original source code.
      )doc"_doc
    )

    .def_prop_ro("size", &dw::Function::size,
      R"doc(
      Return the size taken by this function in the binary.
      )doc"_doc
    )

    .def_prop_ro("ranges", &dw::Function::ranges,
      R"doc(
      Ranges of virtual addresses owned by this function.
      )doc"_doc
    )

    .def_prop_ro("debug_location", &dw::Function::debug_location,
      R"doc(
      Original source code location.
      )doc"_doc
    )

    .def_prop_ro("type", &dw::Function::type,
      R"doc(
      Return the :class:`~.Type` associated with the **return type** of this
      function
      )doc"_doc
    )

    .def_prop_ro("parameters", &dw::Function::parameters,
      R"doc(
      Return the list of parameters used by this function.
      )doc"_doc
    )

    .def_prop_ro("scope", &dw::Function::scope,
      R"doc(
      Scope in which this function is defined
      )doc"_doc
    )
  ;
}

}
