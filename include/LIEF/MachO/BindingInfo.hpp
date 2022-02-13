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
#ifndef LIEF_MACHO_BINDING_INFO_COMMAND_H_
#define LIEF_MACHO_BINDING_INFO_COMMAND_H_
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"
#include "LIEF/Object.hpp"

#include "LIEF/MachO/enums.hpp"


namespace LIEF {
namespace MachO {
class DylibCommand;
class SegmentCommand;
class Symbol;
class BinaryParser;

//! Class that provides an interface over an entry in DyldInfo structure
//!
//! This class does not represent a structure that exists in the Mach-O format
//! specifications but it provides a *view* on an entry of the Dyld binding opcodes.
class LIEF_API BindingInfo : public Object {

  friend class BinaryParser;

  public:
  BindingInfo();
  BindingInfo(BINDING_CLASS cls, BIND_TYPES type,
      uint64_t address,
      int64_t addend = 0,
      int32_t oridnal = 0,
      bool is_weak = false,
      bool is_non_weak_definition = false, uint64_t offset = 0);

  BindingInfo& operator=(BindingInfo other);
  BindingInfo(const BindingInfo& other);
  void swap(BindingInfo& other);

  //! Check if a MachO::SegmentCommand is associated with this binding
  bool has_segment() const;

  //! The MachO::SegmentCommand associated with the BindingInfo or
  //! a nullptr of it is not bind to a SegmentCommand
  const SegmentCommand* segment() const;
  SegmentCommand*       segment();

  //! Check if a MachO::DylibCommand is tied with the BindingInfo
  bool has_library() const;

  //! MachO::DylibCommand associated with the BindingInfo or a nullptr
  //! if not present
  const DylibCommand* library() const;
  DylibCommand*       library();

  //! Check if a MachO::Symbol is associated with the BindingInfo
  bool has_symbol() const;

  //! MachO::Symbol associated with the BindingInfo or
  //! a nullptr if not present
  const Symbol* symbol() const;
  Symbol*       symbol();

  //! Address of the binding
  uint64_t address() const;
  void address(uint64_t addr);

  //! Class of the binding (weak, lazy, ...)
  BINDING_CLASS binding_class() const;
  void binding_class(BINDING_CLASS bind_class);

  //! Type of the binding. Most of the times it's BIND_TYPES::BIND_TYPE_POINTER
  BIND_TYPES binding_type() const;
  void binding_type(BIND_TYPES type);

  int32_t library_ordinal() const;
  void library_ordinal(int32_t ordinal);

  //! Value added to the segment's virtual address when bound
  int64_t addend() const;
  void addend(int64_t addend);

  bool is_weak_import() const;
  void set_weak_import(bool val = true);

  inline bool is_non_weak_definition() const {
    return this->is_non_weak_definition_;
  }

  inline void set_non_weak_definition(bool val) {
    this->is_non_weak_definition_ = val;
  }

  //! Original relative offset of the binding opcodes
  uint64_t original_offset() const;

  virtual ~BindingInfo();

  bool operator==(const BindingInfo& rhs) const;
  bool operator!=(const BindingInfo& rhs) const;

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const BindingInfo& binding_info);

  private:
  BINDING_CLASS   class_ = BINDING_CLASS::BIND_CLASS_STANDARD;
  BIND_TYPES      binding_type_ = BIND_TYPES::BIND_TYPE_POINTER;
  SegmentCommand* segment_ = nullptr;
  Symbol*         symbol_ = nullptr;
  int32_t         library_ordinal_ = 0;
  int64_t         addend_ = 0;
  bool            is_weak_import_ = false;
  bool            is_non_weak_definition_ = false;
  DylibCommand*   library_ = nullptr;
  uint64_t        address_ = 0;
  uint64_t        offset_ = 0;
};

}
}
#endif
