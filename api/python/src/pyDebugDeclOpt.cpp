#include "LIEF/DebugDeclOpt.hpp"
#include "pyLIEF.hpp"

namespace LIEF::py {
template<>
void create<DeclOpt>(nb::module_& m) {
  nb::class_<DeclOpt>(m, "DeclOpt",
    R"doc(
    Configuration options for generated code from debug info.

    This structure configures how the debug information (DWARF/PDB) translated
    into an AST is generated.
    )doc"_doc)

    .def(nb::init<>())
    .def_rw("indentation", &DeclOpt::indentation,
      "The number of spaces for indentation."_doc
    )
    .def_rw("is_cpp", &DeclOpt::is_cpp,
      R"doc(
      Prefer C++ syntax over C syntax.

      If true, the output will use C++ features (e.g., ``bool`` keyword)
      )doc"_doc
    )

    .def_rw("show_extended_annotations", &DeclOpt::show_extended_annotations,
      R"doc(
      Enable extended comments and annotations.

      If true, the generated code will include comments containing low-level
      details such as memory addresses, offsets, type sizes, and original
      source locations.
      )doc"_doc
    )

    .def_rw("include_types", &DeclOpt::include_types,
      R"doc(
      Include full type definitions.

      If true, the output will contain the full definition of types (structs,
      enums, unions).
      )doc"_doc
    )

    .def_rw("desugar", &DeclOpt::desugar,
      R"doc(
      Resolve type aliases (sugar).

      If true, ``typedef``s and type aliases are replaced by their underlying
      canonical types (e.g., ``uint32_t`` might become ``unsigned int``).
      )doc"_doc
    )
  ;
}
}
