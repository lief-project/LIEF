/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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

class LIEF_API ExportInfo : public Object {

  friend class BinaryParser;

  public:
  using flag_list_t = std::vector<EXPORT_SYMBOL_FLAGS>;

  ExportInfo();
  ExportInfo(uint64_t address, uint64_t flags, uint64_t offset = 0);

  ExportInfo& operator=(ExportInfo copy);
  ExportInfo(const ExportInfo& copy);
  void swap(ExportInfo& other);

  uint64_t node_offset() const;

  uint64_t flags() const;
  void flags(uint64_t flags);

  flag_list_t flags_list() const;

  bool has(EXPORT_SYMBOL_FLAGS flag) const;

  EXPORT_SYMBOL_KINDS kind() const;

  uint64_t other() const;

  uint64_t address() const;
  void address(uint64_t addr);

  bool has_symbol() const;

  const Symbol& symbol() const;
  Symbol& symbol();

  Symbol* alias();
  const Symbol* alias() const;

  DylibCommand* alias_library();
  const DylibCommand* alias_library() const;


  virtual ~ExportInfo();

  bool operator==(const ExportInfo& rhs) const;
  bool operator!=(const ExportInfo& rhs) const;

  virtual void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ExportInfo& export_info);

  private:
  uint64_t node_offset_;
  uint64_t flags_;
  uint64_t address_;
  uint64_t other_;
  Symbol* symbol_{nullptr};

  Symbol* alias_{nullptr};
  DylibCommand* alias_location_{nullptr};


};

}
}
#endif
