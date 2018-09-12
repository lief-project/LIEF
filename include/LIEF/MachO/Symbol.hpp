/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

#include "LIEF/MachO/ExportInfo.hpp"
#include "LIEF/MachO/BindingInfo.hpp"


namespace LIEF {
namespace MachO {

class BinaryParser;

class LIEF_API Symbol : public LIEF::Symbol {

  friend class BinaryParser;

  public:
  Symbol(void);

  Symbol(const nlist_32 *cmd);
  Symbol(const nlist_64 *cmd);

  Symbol& operator=(Symbol other);
  Symbol(const Symbol& other);
  void swap(Symbol& other);

  virtual ~Symbol(void);

  uint8_t  type(void) const;
  uint8_t  numberof_sections(void) const;
  uint16_t description(void) const;

  bool has_export_info(void) const;
  const ExportInfo& export_info(void) const;
  ExportInfo& export_info(void);

  bool has_binding_info(void) const;
  const BindingInfo& binding_info(void) const;
  BindingInfo& binding_info(void);

  std::string demangled_name(void) const;

  void type(uint8_t type);
  void numberof_sections(uint8_t nbsections);
  void description(uint16_t desc);

  bool is_external(void) const;

  inline const DylibCommand* library(void) const {
    return this->library_;
  }

  inline DylibCommand* library(void) {
    return this->library_;
  }

  SYMBOL_ORIGINS origin(void) const;

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
