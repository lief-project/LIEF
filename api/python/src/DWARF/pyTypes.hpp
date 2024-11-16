#pragma once

#include <nanobind/nanobind.h>
#include "LIEF/DWARF/types/Base.hpp"
#include "LIEF/DWARF/types/Array.hpp"
#include "LIEF/DWARF/types/ClassLike.hpp"
#include "LIEF/DWARF/types/Pointer.hpp"
#include "LIEF/DWARF/types/Const.hpp"


#include "LIEF/DWARF/types/Typedef.hpp"
#include "LIEF/DWARF/types/Atomic.hpp"
#include "LIEF/DWARF/types/Coarray.hpp"
#include "LIEF/DWARF/types/Dynamic.hpp"
#include "LIEF/DWARF/types/File.hpp"
#include "LIEF/DWARF/types/Immutable.hpp"
#include "LIEF/DWARF/types/Interface.hpp"
#include "LIEF/DWARF/types/PointerToMember.hpp"
#include "LIEF/DWARF/types/RValueRef.hpp"
#include "LIEF/DWARF/types/Reference.hpp"
#include "LIEF/DWARF/types/Restrict.hpp"
#include "LIEF/DWARF/types/SetTy.hpp"
#include "LIEF/DWARF/types/Shared.hpp"
#include "LIEF/DWARF/types/StringTy.hpp"
#include "LIEF/DWARF/types/Subroutine.hpp"
#include "LIEF/DWARF/types/TemplateAlias.hpp"
#include "LIEF/DWARF/types/Thrown.hpp"
#include "LIEF/DWARF/types/Volatile.hpp"
#include "LIEF/DWARF/types/Enum.hpp"

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

      if (Packed::classof(src)) {
        return &typeid(Packed);
      }

      if (Typedef::classof(src)) {
        return &typeid(Typedef);
      }

      if (Atomic::classof(src)) {
        return &typeid(Atomic);
      }

      if (Coarray::classof(src)) {
        return &typeid(Coarray);
      }

      if (Dynamic::classof(src)) {
        return &typeid(Dynamic);
      }

      if (File::classof(src)) {
        return &typeid(File);
      }

      if (Immutable::classof(src)) {
        return &typeid(Immutable);
      }

      if (Interface::classof(src)) {
        return &typeid(Interface);
      }

      if (PointerToMember::classof(src)) {
        return &typeid(PointerToMember);
      }

      if (RValueReference::classof(src)) {
        return &typeid(RValueReference);
      }

      if (Reference::classof(src)) {
        return &typeid(Reference);
      }

      if (Restrict::classof(src)) {
        return &typeid(Restrict);
      }

      if (SetTy::classof(src)) {
        return &typeid(SetTy);
      }

      if (Shared::classof(src)) {
        return &typeid(Shared);
      }

      if (StringTy::classof(src)) {
        return &typeid(StringTy);
      }

      if (Subroutine::classof(src)) {
        return &typeid(Subroutine);
      }

      if (TemplateAlias::classof(src)) {
        return &typeid(TemplateAlias);
      }

      if (Thrown::classof(src)) {
        return &typeid(Thrown);
      }

      if (Volatile::classof(src)) {
        return &typeid(Volatile);
      }

      if (Enum::classof(src)) {
        return &typeid(Enum);
      }
    }
    return &typeid(LIEF::dwarf::Type);
  }
};
}
