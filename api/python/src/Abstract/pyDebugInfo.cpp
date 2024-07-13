#include "LIEF/Abstract/DebugInfo.hpp"
#include "Abstract/init.hpp"

#include "enums_wrapper.hpp"

namespace LIEF::py {
template<>
void create<DebugInfo>(nb::module_& m) {
  nb::class_<DebugInfo> dbg_info(m, "DebugInfo");
  enum_<DebugInfo::FORMAT>(dbg_info, "FORMAT")
    .value("UNKNOWN", DebugInfo::FORMAT::UNKNOWN)
    .value("DWARF", DebugInfo::FORMAT::DWARF)
    .value("PDB", DebugInfo::FORMAT::PDB);

  dbg_info.def_prop_ro("format", &DebugInfo::format,
    R"delim(
    Debug format (PDB/DWARF)
    )delim"
  );
}

}
