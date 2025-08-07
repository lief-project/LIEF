#pragma once

#include <nanobind/nanobind.h>

#include "LIEF/DWARF/DebugInfo.hpp"
#include "LIEF/PDB/DebugInfo.hpp"

namespace nanobind::detail {
template<> struct type_hook<LIEF::DebugInfo> {
  static const std::type_info* get(const LIEF::DebugInfo *src) {
    if (src) {
      if (LIEF::dwarf::DebugInfo::classof(src)) {
        return &typeid(LIEF::dwarf::DebugInfo);
      }

      if (LIEF::pdb::DebugInfo::classof(src)) {
        return &typeid(LIEF::pdb::DebugInfo);
      }
    }
    return &typeid(LIEF::dwarf::Type);
  }
};
}
