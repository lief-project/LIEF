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
#ifndef LIEF_PE_RELOCATION_ENTRY_H
#define LIEF_PE_RELOCATION_ENTRY_H

#include <ostream>

#include "LIEF/Abstract/Relocation.hpp"

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Header.hpp"

namespace LIEF {
namespace PE {

class Relocation;

//! Class which represents an entry of the PE relocation table
//!
//! It extends the LIEF::Relocation object to provide an uniform API across the file formats
class LIEF_API RelocationEntry : public LIEF::Relocation {

  friend class Parser;
  friend class Builder;
  friend class PE::Relocation;

  public:
  enum class BASE_TYPES {
    UNKNOWN        = -1,

    ABS            = 0,
    HIGH           = 1,
    LOW            = 2,
    HIGHLOW        = 3,
    HIGHADJ        = 4,

    MIPS_JMPADDR   = 5,
    ARM_MOV32A     = 5 + 0x101,
    ARM_MOV32      = 5 + 0x102,
    RISCV_HI20     = 5 + 0x103,

    SECTION        = 6,

    REL            = 7,
    ARM_MOV32T     = 7 + 0x201,
    THUMB_MOV32    = 7 + 0x202,
    RISCV_LOW12I   = 7 + 0x203,

    RISCV_LOW12S   = 8,

    IA64_IMM64     = 9,
    MIPS_JMPADDR16 = 9 + 0x300,

    DIR64          = 10,
    HIGH3ADJ       = 11,
  };
  static RelocationEntry from_raw(Header::MACHINE_TYPES arch, uint16_t raw) {
    return RelocationEntry(raw, arch);
  }

  RelocationEntry() = default;
  RelocationEntry(const RelocationEntry& other);
  RelocationEntry& operator=(RelocationEntry other);

  RelocationEntry(uint16_t position, BASE_TYPES type);
  ~RelocationEntry() override = default;

  void swap(RelocationEntry& other);

  //! The address of the relocation
  uint64_t address() const override;

  void address(uint64_t address) override;

  //! The size of the relocatable pointer
  size_t size() const override;

  void size(size_t size) override;

  //! Raw data of the relocation:
  //! - The **high** 4 bits store the relocation type
  //! - The **low** 12 bits store the relocation offset
  uint16_t data() const;

  //! Offset relative to Relocation::virtual_address where the relocation occurs.
  uint16_t position() const {
    return position_;
  }

  //! Type of the relocation
  BASE_TYPES type() const {
    return type_;
  }

  void data(uint16_t data);

  void position(uint16_t position) {
    position_ = position;
  }

  void type(BASE_TYPES type) {
    type_ = type;
  }

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const RelocationEntry& entry);

  private:
  RelocationEntry(uint16_t data, Header::MACHINE_TYPES arch);

  uint16_t               position_ = 0;
  BASE_TYPES             type_ = BASE_TYPES::ABS;
  Header::MACHINE_TYPES  arch_ = Header::MACHINE_TYPES::UNKNOWN;
  PE::Relocation*        relocation_ = nullptr; // Used to compute some information
};

LIEF_API const char* to_string(RelocationEntry::BASE_TYPES e);

}
}
#endif
