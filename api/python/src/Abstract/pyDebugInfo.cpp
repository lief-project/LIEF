#include "pyLIEF.hpp"
#include "LIEF/Abstract/DebugInfo.hpp"
#include "Abstract/init.hpp"

#include <nanobind/stl/string.h>
#include "nanobind/extra/stl/lief_optional.h"

#include "enums_wrapper.hpp"

namespace LIEF::py {
template<>
void create<DebugInfo>(nb::module_& m) {
  nb::class_<DebugInfo> dbg_info(m, "DebugInfo",
    R"doc(
    This class provides a generic interface for accessing debug information
    from different formats such as DWARF and PDB.

    Users can use this interface to access high-level debug features like
    resolving function addresses.

    See: :class:`~lief.pdb.DebugInfo`, :class:`lief.dwarf.DebugInfo`
    )doc"_doc
  );
  enum_<DebugInfo::FORMAT>(dbg_info, "FORMAT")
    .value("UNKNOWN", DebugInfo::FORMAT::UNKNOWN)
    .value("DWARF", DebugInfo::FORMAT::DWARF)
    .value("PDB", DebugInfo::FORMAT::PDB);

  dbg_info
    .def_prop_ro("format", &DebugInfo::format,
      "The actual debug format (PDB/DWARF)"_doc
    )
    .def("find_function_address", &DebugInfo::find_function_address,
      "Attempt to resolve the address of the function specified by ``name``."_doc,
      "name"_a
    );
}

}
