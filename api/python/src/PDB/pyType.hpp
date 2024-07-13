#pragma once

#include <nanobind/nanobind.h>

#include "LIEF/PDB/types/Simple.hpp"
#include "LIEF/PDB/types/Array.hpp"
#include "LIEF/PDB/types/BitField.hpp"
#include "LIEF/PDB/types/ClassLike.hpp"
#include "LIEF/PDB/types/Enum.hpp"
#include "LIEF/PDB/types/Function.hpp"
#include "LIEF/PDB/types/Modifier.hpp"
#include "LIEF/PDB/types/Pointer.hpp"
#include "LIEF/PDB/types/Union.hpp"

namespace nanobind::detail {
template<> struct type_hook<LIEF::pdb::Type> {
  static const std::type_info* get(const LIEF::pdb::Type *src) {
    using namespace LIEF::pdb::types;
    if (src) {
      if (Simple::classof(src)) {
        return &typeid(Simple);
      }

      if (Array::classof(src)) {
        return &typeid(Array);
      }

      if (BitField::classof(src)) {
        return &typeid(BitField);
      }

      if (Class::classof(src)) {
        return &typeid(Class);
      }

      if (Structure::classof(src)) {
        return &typeid(Structure);
      }

      if (Interface::classof(src)) {
        return &typeid(Interface);
      }

      if (Enum::classof(src)) {
        return &typeid(Enum);
      }

      if (Function::classof(src)) {
        return &typeid(Function);
      }

      if (Modifier::classof(src)) {
        return &typeid(Modifier);
      }

      if (Pointer::classof(src)) {
        return &typeid(Pointer);
      }

      if (Union::classof(src)) {
        return &typeid(Union);
      }
    }
    return &typeid(LIEF::pdb::Type);
  }
};
}
