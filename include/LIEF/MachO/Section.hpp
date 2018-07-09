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
#ifndef LIEF_MACHO_SECTION_H_
#define LIEF_MACHO_SECTION_H_
#include <string>
#include <vector>
#include <iostream>
#include <set>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/Section.hpp"

#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/MachO/type_traits.hpp"
#include "LIEF/MachO/Relocation.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;
class SegmentCommand;
class Binary;

class LIEF_API Section : public LIEF::Section {

  friend class BinaryParser;
  friend class Binary;
  friend class SegmentCommand;

  public:
  using content_t   = std::vector<uint8_t>;
  using flag_list_t = std::set<MACHO_SECTION_FLAGS>;

  public:
  Section(void);
  Section(const section_32 *sectionCmd);
  Section(const section_64 *sectionCmd);

  Section(const std::string& name);
  Section(const std::string& name, const content_t& content);

  Section& operator=(Section copy);
  Section(const Section& copy);

  void swap(Section& other);

  virtual ~Section(void);

  // ============================
  // LIEF::Section implementation
  // ============================
  virtual content_t content(void) const override;

  //! @brief Set section content
  virtual void content(const content_t& data) override;

  //! @brief Return the name of the segment holding this section
  const std::string& segment_name(void) const;

  //! @see virtual_address
  uint64_t address(void) const;

  uint32_t                alignment(void) const;
  uint32_t                relocation_offset(void) const;
  uint32_t                numberof_relocations(void) const;
  uint32_t                flags(void) const;
  MACHO_SECTION_TYPES     type(void) const;
  uint32_t                reserved1(void) const;
  uint32_t                reserved2(void) const;
  uint32_t                reserved3(void) const;
  flag_list_t             flags_list(void) const;
  uint32_t                raw_flags(void) const;

  bool                    has_segment(void) const;
  SegmentCommand&         segment(void);
  const SegmentCommand&   segment(void) const;

  void clear(uint8_t v);

  it_relocations relocations(void);
  it_const_relocations relocations(void) const;

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

  bool has(MACHO_SECTION_FLAGS flag) const;

  void add(MACHO_SECTION_FLAGS flag);
  void remove(MACHO_SECTION_FLAGS flag);

  Section& operator+=(MACHO_SECTION_FLAGS flag);
  Section& operator-=(MACHO_SECTION_FLAGS flag);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const Section& rhs) const;
  bool operator!=(const Section& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Section& section);

  private:
  std::string segment_name_;
  uint64_t original_size_{0};
  uint32_t align_{0};
  uint32_t relocations_offset_{0};
  uint32_t nbof_relocations_{0};
  //! @brief `flags_` attribute holds both section's type and section's *flags*
  //!
  //! * Type:  `flags_[7:0]`
  //! * Flags: `flags_[31:8]`
  uint32_t flags_{0};
  uint32_t reserved1_{0};
  uint32_t reserved2_{0};
  uint32_t reserved3_{0};
  content_t content_;
  //! @brief Pointer to the segment holding this section.
  SegmentCommand *segment_{nullptr};
  relocations_t relocations_;
};

}
}
#endif
