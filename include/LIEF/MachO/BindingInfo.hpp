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
#ifndef LIEF_MACHO_BINDING_INFO_H
#define LIEF_MACHO_BINDING_INFO_H
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

//! Class that provides an interface over a *binding* operation.
//!
//! This class does not represent a structure that exists in the Mach-O format
//! specifications but it provides a *view* of a binding operation that is performed
//! by the Dyld binding bytecode (`LC_DYLD_INFO`) or the Dyld chained fixups (`DYLD_CHAINED_FIXUPS`)
//!
//! See: LIEF::MachO::ChainedBindingInfo, LIEF::MachO::DyldBindingInfo
class LIEF_API BindingInfo : public Object {

  friend class BinaryParser;

  public:
  enum class TYPES {
    UNKNOWN = 0,
    DYLD_INFO,  /// Binding associated with the Dyld info opcodes
    CHAINED,    /// Binding associated with the chained fixups
  };

  BindingInfo();

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
  virtual uint64_t address() const;
  virtual void address(uint64_t addr);

  int32_t library_ordinal() const;
  void library_ordinal(int32_t ordinal);

  //! Value added to the segment's virtual address when bound
  int64_t addend() const;
  void addend(int64_t addend);

  bool is_weak_import() const;
  void set_weak_import(bool val = true);

  //! The type of the binding. This type provides the origin
  //! of the binding (LC_DYLD_INFO or LC_DYLD_CHAINED_FIXUPS)
  virtual TYPES type() const = 0;

  ~BindingInfo() override;

  bool operator==(const BindingInfo& rhs) const;
  bool operator!=(const BindingInfo& rhs) const;

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const BindingInfo& binding_info);

  protected:
  SegmentCommand* segment_ = nullptr;
  Symbol*         symbol_ = nullptr;
  int32_t         library_ordinal_ = 0;
  int64_t         addend_ = 0;
  bool            is_weak_import_ = false;
  DylibCommand*   library_ = nullptr;
  uint64_t        address_ = 0;
};

}
}
#endif
