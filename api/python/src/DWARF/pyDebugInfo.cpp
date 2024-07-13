#include "LIEF/Abstract/DebugInfo.hpp"
#include "LIEF/DWARF/DebugInfo.hpp"
#include "LIEF/DWARF/Function.hpp"
#include "DWARF/pyDwarf.hpp"

#include <nanobind/make_iterator.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::DebugInfo>(nb::module_& m) {
  nb::class_<dw::DebugInfo, LIEF::DebugInfo> dbg_info(m, "DebugInfo",
    R"doc(
    This class represents a DWARF debug information. It can embed different
    compilation units which can be accessed through :attr:`~.compilation_units`.

    This class can be instantiated from :attr:`lief.Binary.debug_info`
    )doc"_doc
  );

  dbg_info
    .def("find_function", nb::overload_cast<const std::string&>(&DebugInfo::find_function, nb::const_),
      R"doc(
      Try to find the function with the given name (mangled or not)

      .. code-block:: python

          info: lief.dwarf.DebugInfo = ...
          if func := info.find_function("_ZNSt6localeD1Ev"):
              print("Found")
          if func := info.find_function("std::locale::~locale()"):
              print("Found")
      )doc"_doc, "name"_a
    )

    .def("find_function", nb::overload_cast<uint64_t>(&DebugInfo::find_function, nb::const_),
      R"doc(
      Try to find the function at the given **virtual** address.
      )doc"_doc, "addr"_a
    )

    .def("find_variable", nb::overload_cast<uint64_t>(&DebugInfo::find_variable, nb::const_),
      R"doc(
      Try to find the (static) variable at the given virtual address.
      )doc"_doc, "addr"_a
    )

    .def("find_variable", nb::overload_cast<const std::string&>(&DebugInfo::find_variable, nb::const_),
      R"doc(
      Try to find the variable with the given name. This name can be mangled or not.
      )doc"_doc, "name"_a
    )

    .def("find_type", nb::overload_cast<const std::string&>(&DebugInfo::find_type, nb::const_),
      R"doc(
      Try to find the type with the given name.
      )doc"_doc, "name"_a
    )

    .def_prop_ro("compilation_units",
        [] (DebugInfo& self) {
          auto units = self.compilation_units();
          return nb::make_iterator(
              nb::type<dw::DebugInfo>(), "compilation_units_it", units);
        }, nb::keep_alive<0, 1>(),
        "Iterator on the CompilationUnit embedded in this dwarf"_doc)
  ;
}

}
