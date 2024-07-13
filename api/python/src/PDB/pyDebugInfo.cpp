#include "LIEF/Abstract/DebugInfo.hpp"
#include "LIEF/PDB/DebugInfo.hpp"
#include "PDB/pyPDB.hpp"

#include <nanobind/make_iterator.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::pdb::py {
template<>
void create<pdb::DebugInfo>(nb::module_& m) {
  nb::class_<pdb::DebugInfo, LIEF::DebugInfo> dbg_info(m, "DebugInfo",
    R"doc(
    This class provides an interface for PDB files.

    One can instantiate this class using :func:`lief.pdb.load` or
    :meth:`lief.pdb.DebugInfo.from_file`
    )doc"_doc
  );
  dbg_info
    .def_prop_ro("age", &pdb::DebugInfo::age,
                 "The number of times the PDB file has been written."_doc)

    .def_prop_ro("guid", &pdb::DebugInfo::guid,
                 "Unique identifier of the PDB file."_doc)

    .def_static("from_file", &pdb::DebugInfo::from_file,
      R"doc(
      Instantiate this class from the given PDB file. It returns ``None``
      if the PDB can't be processed.
      )doc"_doc, "filepath"_a
    )

    .def("find_type", &pdb::DebugInfo::find_type,
      R"doc(
      Find the type with the given name
      )doc"_doc, "name"_a
    )

    .def("find_public_symbol", &pdb::DebugInfo::find_public_symbol,
      R"doc(
      Try to find the PublicSymbol from the given name (based on the public symbol stream)
      The function returns ``None`` if the symbol can't be found.

      .. code-block:: python

        debug_info: lief.pdb.DebugInfo = ...
        if sym := debug_info.find_public_symbol("MiSyncSystemPdes"):
            print("found")
      )doc"_doc, "name"_a
    )
    .def_prop_ro("public_symbols",
      [] (pdb::DebugInfo& self) {
        auto symbols = self.public_symbols();
        return nb::make_iterator(
            nb::type<pdb::DebugInfo>(), "public_symbols_it", symbols);
      },
      R"doc(
      Return an iterator over the public symbol stream.
      )doc"_doc, nb::keep_alive<0, 1>())

    .def_prop_ro("compilation_units",
      [] (pdb::DebugInfo& self) {
        auto units = self.compilation_units();
        return nb::make_iterator(
            nb::type<pdb::DebugInfo>(), "compilation_units_it", units);
      },
      R"doc(
      Iterator over the :class:`.CompilationUnit` from the PDB's DBI stream.
      CompilationUnit are also named "Module" in the PDB's official documentation
      )doc"_doc, nb::keep_alive<0, 1>())

    .def_prop_ro("types",
      [] (pdb::DebugInfo& self) {
        auto types = self.types();
        return nb::make_iterator(
            nb::type<pdb::DebugInfo>(), "types_it", types);
      },
      R"doc(
      Return an iterator over the different types registered in this PDB file
      )doc"_doc, nb::keep_alive<0, 1>())
  ;
}

}
