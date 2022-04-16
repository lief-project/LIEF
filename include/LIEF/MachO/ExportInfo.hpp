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
#ifndef LIEF_MACHO_EXPORT_INFO_COMMAND_H_
#define LIEF_MACHO_EXPORT_INFO_COMMAND_H_
#include <vector>
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"
#include "LIEF/types.hpp"

#include "LIEF/MachO/enums.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;
class Symbol;
class DylibCommand;
class Binary;

//! Class that provides an interface over the Dyld export info
//!
//! This class does not represent a structure that exists in the Mach-O format
//! specification but provides a *view* on an entry of the Dyld export trie.
class LIEF_API ExportInfo : public Object {

  friend class BinaryParser;
  friend class Binary;

  public:
  using flag_list_t = std::vector<EXPORT_SYMBOL_FLAGS>;

  ExportInfo();
  ExportInfo(uint64_t address, uint64_t flags, uint64_t offset = 0);

  ExportInfo& operator=(ExportInfo copy);
  ExportInfo(const ExportInfo& copy);
  void swap(ExportInfo& other);

  //! Original offset in the export Trie
  uint64_t node_offset() const;

  //! Some information (EXPORT_SYMBOL_FLAGS) about the export
  //! (like weak export, reexport, ...)
  uint64_t flags() const;
  void flags(uint64_t flags);

  //! The export flags() as a list
  flag_list_t flags_list() const;

  //! Check if the current entry contains the provided EXPORT_SYMBOL_FLAGS
  bool has(EXPORT_SYMBOL_FLAGS flag) const;

  //! The export's kind (regular, thread local, absolute, ...)
  EXPORT_SYMBOL_KINDS kind() const;

  uint64_t other() const;

  //! The address of the export
  uint64_t address() const;
  void address(uint64_t addr);

  //! Check if a symbol is associated with this export
  bool has_symbol() const;

  //! MachO::Symbol associated with this export or a nullptr if no symbol
  const Symbol* symbol() const;
  Symbol* symbol();

  //! If the export is a EXPORT_SYMBOL_FLAGS::EXPORT_SYMBOL_FLAGS_REEXPORT,
  //! this returns the (optional) MachO::Symbol
  Symbol* alias();
  const Symbol* alias() const;

  //! If the export is a EXPORT_SYMBOL_FLAGS::EXPORT_SYMBOL_FLAGS_REEXPORT,
  //! this returns the (optional) library (MachO::DylibCommand)
  DylibCommand* alias_library();
  const DylibCommand* alias_library() const;

  virtual ~ExportInfo();

  bool operator==(const ExportInfo& rhs) const;
  bool operator!=(const ExportInfo& rhs) const;

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ExportInfo& export_info);

  private:
  uint64_t node_offset_ = 0;
  uint64_t flags_ = 0;
  uint64_t address_ = 0;
  uint64_t other_ = 0;
  Symbol* symbol_ = nullptr;

  Symbol* alias_ = nullptr;
  DylibCommand* alias_location_ = nullptr;
};

}
}
#endif
