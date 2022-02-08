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
#ifndef LIEF_MACHO_RELOCATION_COMMAND_H_
#define LIEF_MACHO_RELOCATION_COMMAND_H_
#include <string>
#include <vector>
#include <iostream>
#include <array>

#include "LIEF/Abstract/Relocation.hpp"

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"
#include "LIEF/Object.hpp"

#include "LIEF/MachO/enums.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;

//! Class that represents a Mach-O relocation
//!
//! @see:
//!   * MachO::RelocationObject
//!   * MachO::RelocationDyld
class LIEF_API Relocation : public LIEF::Relocation {

  friend class BinaryParser;

  public:
  using LIEF::Relocation::address;
  using LIEF::Relocation::size;

  Relocation();
  Relocation(uint64_t address, uint8_t type);

  Relocation& operator=(const Relocation& other);
  Relocation(const Relocation& other);
  void swap(Relocation& other);

  ~Relocation() override;

  virtual Relocation* clone() const = 0;

  //! Indicates whether the item containing the address to be
  //! relocated is part of a CPU instruction that uses PC-relative addressing.
  //!
  //! For addresses contained in PC-relative instructions, the CPU adds the address of
  //! the instruction to the address contained in the instruction.
  virtual bool is_pc_relative() const = 0;

  //! Type of the relocation according to the
  //! Relocation::architecture and/or the Relocation::origin
  //!
  //! See:
  //!   * MachO::X86_RELOCATION
  //!   * MachO::X86_64_RELOCATION
  //!   * MachO::PPC_RELOCATION
  //!   * MachO::ARM_RELOCATION
  //!   * MachO::ARM64_RELOCATION
  //!   * MachO::REBASE_TYPES
  virtual uint8_t type() const;

  //! Achitecture targeted by this relocation
  CPU_TYPES architecture() const;

  //! Origin of the relocation
  virtual RELOCATION_ORIGINS origin() const = 0;

  //! ``true`` if the relocation has a symbol associated with
  bool has_symbol() const;

  //! Symbol associated with the relocation, if any,
  //! otherwise a nullptr.
  Symbol* symbol();
  const Symbol* symbol() const;

  //! ``true`` if the relocation has a section associated with
  bool has_section() const;

  //! Section associated with the relocation, if any,
  //! otherwise a nullptr.
  Section* section();
  const Section* section() const;

  //! ``true`` if the relocation has a SegmentCommand associated with
  bool has_segment() const;

  //! SegmentCommand associated with the relocation, if any,
  //! otherwise a nullptr.
  SegmentCommand* segment();
  const SegmentCommand* segment() const;

  virtual void pc_relative(bool val) = 0;
  virtual void type(uint8_t type);

  bool operator==(const Relocation& rhs) const;
  bool operator!=(const Relocation& rhs) const;

  void accept(Visitor& visitor) const override;

  virtual std::ostream& print(std::ostream& os) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Relocation& relocation);

  protected:
  Symbol*         symbol_ = nullptr;
  uint8_t         type_ = 0;
  CPU_TYPES       architecture_ = CPU_TYPES::CPU_TYPE_ANY;
  Section*        section_ = nullptr;
  SegmentCommand* segment_ = nullptr;
};

}
}
#endif
