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
#ifndef LIEF_MACHO_RELOCATION_FIXUP_H
#define LIEF_MACHO_RELOCATION_FIXUP_H
#include <iostream>
#include <memory>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/MachO/Relocation.hpp"

namespace LIEF {
namespace MachO {

namespace details {
struct dyld_chained_ptr_arm64e_rebase;
struct dyld_chained_ptr_arm64e_auth_rebase;
struct dyld_chained_ptr_64_rebase;
struct dyld_chained_ptr_32_rebase;
}

class BinaryParser;
class Builder;

//! Class that represents a rebase relocation found in the LC_DYLD_CHAINED_FIXUPS command.
//!
//! This class extends LIEF::Relocation in which LIEF::Relocation::address is set to
//! the absolute virtual address where the relocation must take place (e.g. `0x10000d270`).
//!
//! On the other hand, RelocationFixup::target contains the value that should be
//! set at LIEF::Relocation::address if the imagebase is LIEF::Binary::imagebase (e.g. `0x1000073a8`).
//!
//! If the Mach-O loader chooses another base address (like 0x7ff100000), it must set
//! `0x10000d270` to `0x7ff1073a8`.
class LIEF_API RelocationFixup : public Relocation {

  friend class BinaryParser;
  friend class Builder;

  public:
  RelocationFixup() = delete;
  RelocationFixup(DYLD_CHAINED_PTR_FORMAT fmt, uint64_t imagebase);

  RelocationFixup& operator=(const RelocationFixup&);
  RelocationFixup(const RelocationFixup&);

  RelocationFixup& operator=(RelocationFixup&&);
  RelocationFixup(RelocationFixup&&);

  ~RelocationFixup() override;

  Relocation* clone() const override;

  //! Not relevant for this kind of relocation
  bool is_pc_relative() const override;

  //! Origin of the relocation. For this concrete object, it
  //! should be RELOCATION_ORIGINS::ORIGIN_CHAINED_FIXUPS
  RELOCATION_ORIGINS origin() const override;

  inline DYLD_CHAINED_PTR_FORMAT ptr_format() const {
    return ptr_fmt_;
  }

  //! The value that should be set at LIEF::Relocation::address
  //! if the imagebase is LIEF::Binary::imagebase. Otherwise, it should
  //! be: target() - LIEF::Binary::imagebase() + new_imagebase
  uint64_t target() const;
  void target(uint64_t target);

  //! Not relevant for this kind of relocation
  void pc_relative(bool) override;

  inline uint32_t offset() const {
    return offset_;
  }

  inline void offset(uint32_t offset) {
    offset_ = offset;
  }

  //! The address of this relocation is bound to its offset.
  uint64_t address() const override;

  //! Changing the address means changing the offset
  void address(uint64_t address) override;

  bool operator==(const RelocationFixup& rhs) const;
  bool operator!=(const RelocationFixup& rhs) const;

  void accept(Visitor& visitor) const override;

  static bool classof(const Relocation& r);

  std::ostream& print(std::ostream& os) const override;

  private:
  enum class REBASE_TYPES {
    UNKNOWN = 0,

    ARM64E_REBASE,
    ARM64E_AUTH_REBASE,
    PTR64_REBASE,
    PTR32_REBASE,
  };

  void set(const details::dyld_chained_ptr_arm64e_rebase& fixup);
  void set(const details::dyld_chained_ptr_arm64e_auth_rebase& fixup);
  void set(const details::dyld_chained_ptr_64_rebase& fixup);
  void set(const details::dyld_chained_ptr_32_rebase& fixup);

  DYLD_CHAINED_PTR_FORMAT ptr_fmt_;
  uint64_t imagebase_ = 0;
  uint32_t offset_ = 0;

  REBASE_TYPES rtypes_ = REBASE_TYPES::UNKNOWN;

  union {
    details::dyld_chained_ptr_arm64e_rebase*      arm64_rebase_ = nullptr;
    details::dyld_chained_ptr_arm64e_auth_rebase* arm64_auth_rebase_;
    details::dyld_chained_ptr_64_rebase*          p64_rebase_;
    details::dyld_chained_ptr_32_rebase*          p32_rebase_;
  };
};

}
}
#endif
