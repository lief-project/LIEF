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

struct nlist_32;
struct nlist_64;

class LIEF_API Symbol : public LIEF::Symbol {

  friend class BinaryParser;

  public:
  Symbol();

  Symbol(const nlist_32 *cmd);
  Symbol(const nlist_64 *cmd);

  Symbol& operator=(Symbol other);
  Symbol(const Symbol& other);
  void swap(Symbol& other);

  virtual ~Symbol();

  uint8_t  type() const;
  uint8_t  numberof_sections() const;
  uint16_t description() const;

  bool has_export_info() const;
  const ExportInfo& export_info() const;
  ExportInfo& export_info();

  bool has_binding_info() const;
  const BindingInfo& binding_info() const;
  BindingInfo& binding_info();

  std::string demangled_name() const;

  void type(uint8_t type);
  void numberof_sections(uint8_t nbsections);
  void description(uint16_t desc);

  bool is_external() const;

  inline const DylibCommand* library() const {
    return this->library_;
  }

  inline DylibCommand* library() {
    return this->library_;
  }

  SYMBOL_ORIGINS origin() const;

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const Symbol& rhs) const;
  bool operator!=(const Symbol& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Symbol& symbol);

  private:
  inline void library(DylibCommand& library) {
    this->library_ = &library;
  }

  uint8_t  type_;
  uint8_t  numberof_sections_;
  uint16_t description_;

  BindingInfo* binding_info_{nullptr};
  ExportInfo* export_info_{nullptr};

  DylibCommand* library_{nullptr};

  SYMBOL_ORIGINS origin_;
};

}
}
#endif
