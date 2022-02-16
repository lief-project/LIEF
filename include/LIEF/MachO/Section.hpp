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
#ifndef LIEF_MACHO_SECTION_H_
#define LIEF_MACHO_SECTION_H_
#include <string>
#include <vector>
#include <iostream>
#include <set>
#include <memory>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/Section.hpp"

#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/iterators.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;
class SegmentCommand;
class Binary;

namespace details {
struct section_32;
struct section_64;
}

//! Class that represents a Mach-O section
class LIEF_API Section : public LIEF::Section {

  friend class BinaryParser;
  friend class Binary;
  friend class SegmentCommand;

  public:

  using content_t   = std::vector<uint8_t>;
  using flag_list_t = std::set<MACHO_SECTION_FLAGS>;

  //! Internal container for storing Mach-O Relocation
  using relocations_t = std::vector<std::unique_ptr<Relocation>>;

  //! Iterator which outputs Relocation&
  using it_relocations = ref_iterator<relocations_t&, Relocation*>;

  //! Iterator which outputs const Relocation&
  using it_const_relocations = const_ref_iterator<const relocations_t&, const Relocation*>;

  public:
  Section();
  Section(const details::section_32& section_cmd);
  Section(const details::section_64& section_cmd);

  Section(std::string name);
  Section(std::string name, content_t content);

  Section& operator=(Section copy);
  Section(const Section& copy);

  void swap(Section& other);

  ~Section() override;

  span<const uint8_t> content() const override;

  //! Update the content of the section
  void content(const content_t& data) override;

  //! Return the name of the segment linked to this section
  const std::string& segment_name() const;

  //! Virtual base address of the section
  uint64_t address() const;

  //! Section alignment as a power of 2
  uint32_t alignment() const;

  //! Offset of the relocation table. This value should be 0
  //! for executable and libraries as the relocations are managed by the DyldInfo::rebase
  //!
  //! Other the other hand, for object files (``.o``) this value should not be 0
  //!
  //! @see numberof_relocations
  //! @see relocations
  uint32_t relocation_offset() const;

  //! Number of relocations associated with this section
  uint32_t numberof_relocations() const;

  //! Section's flags masked with SECTION_FLAGS_MASK (see: MACHO_SECTION_FLAGS)
  //!
  //! @see flags
  uint32_t flags() const;

  //! Type of the section. This value can help to determine
  //! the purpose of the section (e.g. MACHO_SECTION_TYPES::MACHO_SECTION_TYPES)
  MACHO_SECTION_TYPES type() const;

  //! According to the official ``loader.h`` file, this value is reserved
  //! for *offset* or *index*
  uint32_t reserved1() const;

  //! According to the official ``loader.h`` file, this value is reserved
  //! for *count* or *sizeof*
  uint32_t reserved2() const;

  //! This value is only present for 64 bits Mach-O files. In that case,
  //! the value is *reserved*.
  uint32_t reserved3() const;

  //! Return the Section::flags as an std::set of MACHO_SECTION_FLAGS
  //!
  //! @see flags
  flag_list_t flags_list() const;

  //! Section flags without applying the SECTION_FLAGS_MASK mask
  uint32_t raw_flags() const;

  //! Check if this section is correctly linked with a MachO::SegmentCommand
  bool has_segment() const;

  //! The segment associated with this section or a nullptr
  //! if not present
  SegmentCommand* segment();
  const SegmentCommand* segment() const;

  //! Clear the content of this section by filling its values
  //! with the byte provided in parameter
  void clear(uint8_t v);

  //! Return an iterator over the MachO::Relocation associated with this section
  //!
  //! This iterator is likely to be empty of executable and libraries while it should not
  //! for object files (``.o``)
  it_relocations relocations();
  it_const_relocations relocations() const;

  void segment_name(const std::string& name);
  void address(uint64_t address);
  void alignment(uint32_t align);
  void relocation_offset(uint32_t relocOffset);
  void numberof_relocations(uint32_t nbReloc);
  void flags(uint32_t flags);
  void flags(flag_list_t flags);
  void type(MACHO_SECTION_TYPES type);
  void reserved1(uint32_t reserved1);
  void reserved2(uint32_t reserved2);
  void reserved3(uint32_t reserved3);

  //! Check if the section has the given MACHO_SECTION_FLAGS flag
  bool has(MACHO_SECTION_FLAGS flag) const;

  //! Append a MACHO_SECTION_FLAGS to the current section
  void add(MACHO_SECTION_FLAGS flag);

  //! Remove a MACHO_SECTION_FLAGS to the current section
  void remove(MACHO_SECTION_FLAGS flag);

  Section& operator+=(MACHO_SECTION_FLAGS flag);
  Section& operator-=(MACHO_SECTION_FLAGS flag);

  void accept(Visitor& visitor) const override;

  bool operator==(const Section& rhs) const;
  bool operator!=(const Section& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Section& section);

  private:
  std::string segment_name_;
  uint64_t original_size_ = 0;
  uint32_t align_ = 0;
  uint32_t relocations_offset_ = 0;
  uint32_t nbof_relocations_ = 0;
  uint32_t flags_ = 0;
  uint32_t reserved1_ = 0;
  uint32_t reserved2_ = 0;
  uint32_t reserved3_ = 0;
  content_t content_;
  SegmentCommand *segment_ = nullptr;
  relocations_t relocations_;
};

}
}
#endif
