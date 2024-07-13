#include "LIEF/PDB/PublicSymbol.hpp"
#include "PDB/pyPDB.hpp"

#include <nanobind/make_iterator.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::pdb::py {
template<>
void create<PublicSymbol>(nb::module_& m) {
  nb::class_<PublicSymbol> clazz(m, "PublicSymbol",
    R"doc(
    This class provides general information (RVA, name) about a symbol
    from the PDB's public symbol stream (or Public symbol hash stream)
    )doc"_doc
  );
  clazz
    .def_prop_ro("name", &PublicSymbol::name,
                 "Name of the symbol"_doc)

    .def_prop_ro("section_name", &PublicSymbol::section_name,
      R"doc(
      Name of the section in which this symbol is defined (e.g. ``.text``).
      This function returns an empty string if the section's name can't be found
      )doc"_doc
    )

    .def_prop_ro("RVA", &PublicSymbol::RVA,
      R"doc(
      **Relative** Virtual Address of this symbol.

      This function returns 0 if the RVA can't be computed.
      )doc"_doc
    )

    .def_prop_ro("demangled_name", &PublicSymbol::demangled_name,
                 "Demangled representation of the symbol"_doc)
  ;
}

}
