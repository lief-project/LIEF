#include "LIEF/DWARF/CompilationUnit.hpp"
#include "LIEF/DWARF/Function.hpp"
#include "LIEF/DWARF/Variable.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "DWARF/pyDwarf.hpp"
#include "DWARF/pyTypes.hpp"

#include "enums_wrapper.hpp"

#include <nanobind/make_iterator.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::CompilationUnit>(nb::module_& m) {
  nb::class_<dw::CompilationUnit> CU(m, "CompilationUnit",
    R"doc(
    This class represents a DWARF compilation unit
    )doc"_doc
  );

  nb::class_<dw::CompilationUnit::Language> Lang(CU, "Language",
    R"doc(
    Languages supported by the DWARF (v5) format.
    See: https://dwarfstd.org/languages.html

    Some languages (like C++11, C++17, ..) have a version (11, 17, ...) which
    is stored in a dedicated attribute: :attr:`~.version`
    )doc"_doc
  );

  enum_<dw::CompilationUnit::Language::LANG>(Lang, "LANG")
    .value("UNKNOWN", dw::CompilationUnit::Language::LANG::UNKNOWN)
    .value("C", dw::CompilationUnit::Language::LANG::C)
    .value("CPP", dw::CompilationUnit::Language::LANG::CPP)
    .value("RUST", dw::CompilationUnit::Language::LANG::RUST)
    .value("DART", dw::CompilationUnit::Language::LANG::DART);

  Lang
    .def_rw("lang", &dw::CompilationUnit::Language::lang,
            "The language itself")
    .def_rw("version", &dw::CompilationUnit::Language::version,
            "Version of the language (e.g. 17 for C++17)");

  CU
    .def_prop_ro("name", &dw::CompilationUnit::name,
      R"doc(
      Name of the file associated with this compilation unit (e.g. ``test.cpp``)
      Return an **empty** string if the name is not found or can't be resolved

      This value matches the ``DW_AT_name`` attribute.
      )doc"_doc
    )
    .def_prop_ro("producer", &dw::CompilationUnit::producer,
      R"doc(
      Information about the program (or library) that generated this compilation
      unit. For instance, it can output: ``Debian clang version 17.0.6``.

      It returns an **empty** string if the producer is not present or can't be
      resolved.

      This value matches the ``DW_AT_producer`` attribute.
      )doc"_doc

    )

    .def_prop_ro("compilation_dir", &dw::CompilationUnit::compilation_dir,
      R"doc(
      Return the path to the directory in which the compilation took place for
      compiling this compilation unit (e.g. ``/workdir/build``)

      It returns an **empty** string if the entry is not present or can't be
      resolved.

      This value matches the ``DW_AT_comp_dir`` attribute.
      )doc"_doc
    )

    .def_prop_ro("language", &dw::CompilationUnit::language,
      R"doc(
      Original language of this compilation unit.

      This value matches the ``DW_AT_language`` attribute.
      )doc"_doc
    )

    .def_prop_ro("low_address", &dw::CompilationUnit::low_address,
      R"doc(
      Return the lowest virtual address owned by this compilation unit.
      )doc"_doc
    )

    .def_prop_ro("high_address", &dw::CompilationUnit::high_address,
      R"doc(
      Return the highest virtual address owned by this compilation unit
      )doc"_doc
    )

    .def_prop_ro("size", &dw::CompilationUnit::size,
      R"doc(
      Return the size of the compilation unit according to its range of address.

      If the compilation is fragmented (i.e. there are some address ranges
      between the lowest address and the highest that are not owned by the CU),
      then it returns the sum of **all** the address ranges owned by this CU.

      If the compilation unit is **not** fragmented, then it basically returns
      ``high_address - low_address``.
      )doc"_doc
    )

    .def_prop_ro("ranges", &dw::CompilationUnit::ranges,
      R"doc(
      Return a list of address ranges owned by this compilation unit.

      If the compilation unit owns a contiguous range, it returns
      **a single** range.
      )doc"_doc
    )

    .def("find_function",
         nb::overload_cast<const std::string&>(&dw::CompilationUnit::find_function, nb::const_),
         R"doc(
         Try to find the function whose name is given in parameter.

         The provided name can be demangled.
         )doc"_doc, "name"_a
    )

    .def("find_function",
         nb::overload_cast<uint64_t>(&dw::CompilationUnit::find_function, nb::const_),
         R"doc(
         Try to find the function at the given address
         )doc"_doc, "addr"_a
    )

    .def("find_variable",
         nb::overload_cast<uint64_t>(&dw::CompilationUnit::find_variable, nb::const_),
         R"doc(
         Try to find the variable at the given address
         )doc"_doc, "addr"_a
    )

    .def("find_variable",
         nb::overload_cast<const std::string&>(&dw::CompilationUnit::find_variable, nb::const_),
         R"doc(
         Try to find the variable with the given name (mangled or not)
         )doc"_doc, "name"_a
    )

    .def_prop_ro("types",
        [] (dw::CompilationUnit& self) {
          auto types = self.types();
          return nb::make_iterator(nb::type<dw::CompilationUnit>(), "types_it", types);
        }, nb::keep_alive<0, 1>(),
        R"doc(
        Return an iterator over the different types defined in this
        compilation unit.
        )doc"_doc
    )

    .def_prop_ro("functions",
        [] (dw::CompilationUnit& self) {
          auto functions = self.functions();
          return nb::make_iterator(
              nb::type<dw::CompilationUnit>(), "functions_it", functions);
        }, nb::keep_alive<0, 1>(),
        R"delim(
        Return an iterator over the functions implemented in this compilation
        unit.

        Note that this iterator only iterates over the functions that have a
        **concrete** implementation in the compilation unit.

        For instance with this code:

        .. code-block:: cpp

          inline const char* get_secret_env() {
            return getenv("MY_SECRET_ENV");
          }

          int main() {
            printf("%s", get_secret_env());
            return 0;
          }

        The iterator will only return **one function** for ``main`` since
        ``get_secret_env`` is inlined and thus, its implementation is located in
        ``main``.
        )delim"_doc
    )

    .def_prop_ro("variables",
        [] (dw::CompilationUnit& self) {
          auto variables = self.variables();
          return nb::make_iterator(
              nb::type<dw::CompilationUnit>(), "vars_it", variables);
        }, nb::keep_alive<0, 1>(),
        R"delim(
        Return an iterator over the variables defined in the any scope
        of this compilation unit:

        .. code-block:: cpp

            static int A = 1; // Returned by the iterator
            static const char* B = "Hello"; // Returned by the iterator

            int get() {
              static int C = 2; // Returned by the iterator
              return C;
            }
        )delim"_doc
    )
  ;
}

}
