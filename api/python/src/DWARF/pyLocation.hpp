#ifndef PY_LIEF_DWARF_LOCATION_H
#define PY_LIEF_DWARF_LOCATION_H
#include "LIEF/DWARF/Location.hpp"

#include <typeinfo>

#include <nanobind/nanobind.h>

namespace nanobind::detail {
template<> struct type_hook<LIEF::dwarf::Location> {
  static const std::type_info* get(const LIEF::dwarf::Location* src) {
    namespace dw = LIEF::dwarf;
    if (src == nullptr) {
      return &typeid(dw::Location);
    }
    switch (src->type) {
      case dw::Location::Type::REG: return &typeid(dw::RegisterLoc);
      case dw::Location::Type::ADDRESS: return &typeid(dw::AddressLoc);
      case dw::Location::Type::FRAME_BASE: return &typeid(dw::FrameBaseLoc);
      case dw::Location::Type::REGISTER_OFFSET:
        return &typeid(dw::RegisterOffsetLoc);
      case dw::Location::Type::EXPRESSION: return &typeid(dw::ExpressionLoc);
      case dw::Location::Type::UNAVAILABLE: return &typeid(dw::UnavailableLoc);
      case dw::Location::Type::COMPOSITE: return &typeid(dw::CompositeLocation);
      case dw::Location::Type::UNKNOWN: break;
    }
    return &typeid(dw::Location);
  }
};
}

#endif
