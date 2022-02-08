/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#ifndef LIEF_MACHO_SYMBOL_H_
#define LIEF_MACHO_SYMBOL_H_

#include <iostream>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/Symbol.hpp"

#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/MachO/enums.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;
class BindingInfo;
class ExportInfo;
class DylibCommand;

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

  public:
  Symbol();

  Symbol(const details::nlist_32& cmd);
  Symbol(const details::nlist_64& cmd);

  Symbol& operator=(Symbol other);
  Symbol(const Symbol& other);
  void swap(Symbol& other);

  ~Symbol() override;

  uint8_t type() const;

  //! It returns the number of sections in which this symbol can be found.
  //! If the symbol can't be found in any section, it returns 0 (NO_SECT)
  uint8_t numberof_sections() const;

  //! Return information about the symbol (SYMBOL_DESCRIPTIONS)
  uint16_t description() const;

  //! True if the symbol is associated with an ExportInfo
  //! This value is set when the symbol comes from the Dyld Export trie
  bool has_export_info() const;

  //! Return the ExportInfo associated with this symbol (or nullptr if not present)
  //! @see has_export_info
  const ExportInfo* export_info() const;
  ExportInfo* export_info();

  //! True if the symbol is associated with a BindingInfo
  //! This value is set when the symbol comes from the Dyld symbol bindings
  bool has_binding_info() const;

  //! Return the BindingInfo associated with this symbol (or nullptr if not present)
  //! @see has_binding_info
  const BindingInfo* binding_info() const;
  BindingInfo* binding_info();

  //! Try to demangle the symbol or return an empty string if it is not possible
  std::string demangled_name() const;

  //! True if the symbol is defined as an external symbol.
  //!
  //! This function check if the flag N_LIST_TYPES::N_UNDF is set
  bool is_external() const;

  //! Return the library in which the symbol is defined.
  //! It returns a null pointer if the library can't be resolved
  inline const DylibCommand* library() const {
    return library_;
  }

  inline DylibCommand* library() {
    return library_;
  }

  //! Return the origin of the symbol: from LC_SYMTAB command or from the Dyld information
  SYMBOL_ORIGINS origin() const;

  void type(uint8_t type);
  void numberof_sections(uint8_t nbsections);
  void description(uint16_t desc);

  void accept(Visitor& visitor) const override;

  bool operator==(const Symbol& rhs) const;
  bool operator!=(const Symbol& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Symbol& symbol);

  private:
  inline void library(DylibCommand& library) {
    this->library_ = &library;
  }

  uint8_t type_ = 0;
  uint8_t numberof_sections_ = 0;
  uint16_t description_ = 0;

  BindingInfo* binding_info_ = nullptr;
  ExportInfo* export_info_ = nullptr;

  DylibCommand* library_ = nullptr;

  SYMBOL_ORIGINS origin_ = SYMBOL_ORIGINS::SYM_ORIGIN_UNKNOWN;
};

}
}
#endif
