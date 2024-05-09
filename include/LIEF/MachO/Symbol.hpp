/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIEF_MACHO_SYMBOL_H
#define LIEF_MACHO_SYMBOL_H

#include <ostream>

#include "LIEF/visibility.h"

#include "LIEF/Abstract/Symbol.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;
class BindingInfo;
class ExportInfo;
class DylibCommand;
class Binary;

namespace details {
struct nlist_32;
struct nlist_64;
}

//! Class that represents a Symbol in a Mach-O file.
//!
//! A Mach-O symbol can come from:
//! 1. The symbols command (LC_SYMTAB / SymbolCommand)
//! 2. The Dyld Export trie
//! 3. The Dyld Symbol bindings
class LIEF_API Symbol : public LIEF::Symbol {

  friend class BinaryParser;
  friend class Binary;

  public:

  //! Category of the symbol when the symbol comes from the `LC_SYMTAB` command.
  //! The category is defined according to the `LC_DYSYMTAB` (DynamicSymbolCommand) command.
  enum class CATEGORY {
    NONE = 0,
    LOCAL,
    EXTERNAL,
    UNDEFINED,

    INDIRECT_ABS,
    INDIRECT_LOCAL,
  };

  enum class ORIGIN {
    UNKNOWN     = 0,
    DYLD_EXPORT = 1,
    DYLD_BIND   = 2, /// The symbol comes from the binding opcodes
    LC_SYMTAB   = 3,
  };

  Symbol() = default;

  Symbol(const details::nlist_32& cmd);
  Symbol(const details::nlist_64& cmd);

  Symbol& operator=(Symbol other);
  Symbol(const Symbol& other);
  void swap(Symbol& other) noexcept;

  ~Symbol() override = default;

  uint8_t type() const {
    return type_;
  }

  //! It returns the number of sections in which this symbol can be found.
  //! If the symbol can't be found in any section, it returns 0 (NO_SECT)
  uint8_t numberof_sections() const {
    return numberof_sections_;
  }

  //! Return information about the symbol (SYMBOL_DESCRIPTIONS)
  uint16_t description() const {
    return description_;
  }

  //! True if the symbol is associated with an ExportInfo
  //! This value is set when the symbol comes from the Dyld Export trie
  bool has_export_info() const {
    return export_info() != nullptr;
  }

  //! Return the ExportInfo associated with this symbol (or nullptr if not present)
  //! @see has_export_info
  const ExportInfo* export_info() const {
    return export_info_;
  }
  ExportInfo* export_info() {
    return export_info_;
  }

  //! True if the symbol is associated with a BindingInfo
  //! This value is set when the symbol comes from the Dyld symbol bindings
  bool has_binding_info() const {
    return binding_info() != nullptr;
  }

  //! Return the BindingInfo associated with this symbol (or nullptr if not present)
  //! @see has_binding_info
  const BindingInfo* binding_info() const {
    return binding_info_;
  }

  BindingInfo* binding_info() {
    return binding_info_;
  }

  //! Try to demangle the symbol or return an empty string if it is not possible
  std::string demangled_name() const;

  //! True if the symbol is defined as an external symbol.
  //!
  //! This function check if the flag N_LIST_TYPES::N_UNDF is set
  bool is_external() const;

  //! Return the library in which the symbol is defined.
  //! It returns a null pointer if the library can't be resolved
  const DylibCommand* library() const {
    return library_;
  }

  DylibCommand* library() {
    return library_;
  }

  //! Return the origin of the symbol: from LC_SYMTAB command or from the Dyld information
  ORIGIN origin() const {
    return origin_;
  }

  //! Category of the symbol according to the `LC_DYSYMTAB` command
  CATEGORY category() const {
    return category_;
  }

  void type(uint8_t type) {
    type_ = type;
  }
  void numberof_sections(uint8_t nbsections) {
    numberof_sections_ = nbsections;
  }
  void description(uint16_t desc) {
    description_ = desc;
  }

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Symbol& symbol);

  static const Symbol& indirect_abs();
  static const Symbol& indirect_local();

  private:
  Symbol(CATEGORY cat) :
    category_(cat)
  {}
  void library(DylibCommand& library) {
    this->library_ = &library;
  }

  uint8_t type_ = 0;
  uint8_t numberof_sections_ = 0;
  uint16_t description_ = 0;

  BindingInfo* binding_info_ = nullptr;
  ExportInfo* export_info_ = nullptr;

  DylibCommand* library_ = nullptr;

  ORIGIN origin_ = ORIGIN::UNKNOWN;
  CATEGORY category_ = CATEGORY::NONE;
};

LIEF_API const char* to_string(Symbol::ORIGIN e);
LIEF_API const char* to_string(Symbol::CATEGORY e);

}
}
#endif
