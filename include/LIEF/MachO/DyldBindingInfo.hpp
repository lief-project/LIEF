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
#ifndef LIEF_MACHO_DYLD_INFO_BINDING_INFO_H
#define LIEF_MACHO_DYLD_INFO_BINDING_INFO_H
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"
#include "LIEF/MachO/BindingInfo.hpp"
#include "LIEF/MachO/enums.hpp"

namespace LIEF {
namespace MachO {

//! This class represents a symbol binding operation associated with
//! the LC_DYLD_INFO bytecode.
//!
//! It does not represent a structure that exists in the Mach-O format
//! specifications but it provides a *view* on an entry of the Dyld binding opcodes.
//!
//! @see: BindingInfo
class LIEF_API DyldBindingInfo : public BindingInfo {

  friend class BinaryParser;

  public:
  DyldBindingInfo();
  DyldBindingInfo(BINDING_CLASS cls, BIND_TYPES type,
                  uint64_t address, int64_t addend = 0,
                  int32_t oridnal = 0, bool is_weak = false,
                  bool is_non_weak_definition = false, uint64_t offset = 0);

  DyldBindingInfo& operator=(DyldBindingInfo other);
  DyldBindingInfo(const DyldBindingInfo& other);

  DyldBindingInfo& operator=(DyldBindingInfo&&);
  DyldBindingInfo(DyldBindingInfo&&);

  void swap(DyldBindingInfo& other);

  //! Class of the binding (weak, lazy, ...)
  BINDING_CLASS binding_class() const;
  void binding_class(BINDING_CLASS bind_class);

  //! Type of the binding. Most of the times it's BIND_TYPES::BIND_TYPE_POINTER
  BIND_TYPES binding_type() const;
  void binding_type(BIND_TYPES type);

  inline bool is_non_weak_definition() const {
    return this->is_non_weak_definition_;
  }

  inline void set_non_weak_definition(bool val) {
    this->is_non_weak_definition_ = val;
  }

  //! Original relative offset of the binding opcodes
  uint64_t original_offset() const;

  inline BindingInfo::TYPES type() const override {
    return BindingInfo::TYPES::DYLD_INFO;
  }

  ~DyldBindingInfo() override;

  bool operator==(const DyldBindingInfo& rhs) const;
  bool operator!=(const DyldBindingInfo& rhs) const;

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const DyldBindingInfo& binding_info);

  static bool classof(const BindingInfo& info);

  private:
  BINDING_CLASS   class_ = BINDING_CLASS::BIND_CLASS_STANDARD;
  BIND_TYPES      binding_type_ = BIND_TYPES::BIND_TYPE_POINTER;
  bool            is_non_weak_definition_ = false;
  uint64_t        offset_ = 0;
};

}
}
#endif
