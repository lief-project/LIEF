#pragma once

#include <nanobind/nanobind.h>
#include "LIEF/DWARF/types/Base.hpp"
#include "LIEF/DWARF/types/Array.hpp"
#include "LIEF/DWARF/types/ClassLike.hpp"
#include "LIEF/DWARF/types/Pointer.hpp"
#include "LIEF/DWARF/types/Const.hpp"

namespace nanobind::detail {
template<> struct type_hook<LIEF::dwarf::Type> {
  static const std::type_info* get(const LIEF::dwarf::Type *src) {
    using namespace LIEF::dwarf::types;
    if (src) {
      if (Base::classof(src)) {
        return &typeid(Base);
      }

      if (Array::classof(src)) {
        return &typeid(Array);
      }

      if (Const::classof(src)) {
        return &typeid(Const);
      }

      if (Pointer::classof(src)) {
        return &typeid(Pointer);
      }

      if (Structure::classof(src)) {
        return &typeid(Structure);
      }

      if (Class::classof(src)) {
        return &typeid(Class);
      }

      if (Union::classof(src)) {
        return &typeid(Union);
      }
    }
    return &typeid(LIEF::dwarf::Type);
  }
};
}
