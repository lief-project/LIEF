#include "LIEF/rust/DWARF/editor/Type.hpp"
#include "LIEF/rust/DWARF/editor/PointerType.hpp"

std::unique_ptr<DWARF_editor_PointerType> DWARF_editor_Type::pointer_to() const {
  return details::try_unique<DWARF_editor_PointerType>(
    get().pointer_to()
  );
}

