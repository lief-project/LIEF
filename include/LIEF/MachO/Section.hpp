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

  public:
    Section(void);
    Section(const section_32 *sectionCmd);
    Section(const section_64 *sectionCmd);

    Section& operator=(const Section& copy);
    Section(const Section& copy);

    virtual ~Section(void);

    // ============================
    // LIEF::Section implementation
    // ============================
    //! @todo To implement
    virtual std::vector<uint8_t> content(void) const override;

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
    std::set<MACHO_SECTION_FLAGS> flags_list(void) const;
    uint32_t                raw_flags(void) const;

    it_relocations relocations(void);
    it_const_relocations relocations(void) const;

    void segment_name(const std::string& name);
    void address(uint64_t address);
    void alignment(uint32_t align);
    void relocation_offset(uint32_t relocOffset);
    void numberof_relocations(uint32_t nbReloc);
    void flags(uint32_t flags);
    void type(MACHO_SECTION_TYPES type);
    void reserved1(uint32_t reserved1);
    void reserved2(uint32_t reserved2);
    void reserved3(uint32_t reserved3);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const Section& rhs) const;
    bool operator!=(const Section& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const Section& section);

  private:
    std::string segment_name_;
    uint64_t original_size_;
    uint32_t align_;
    uint32_t relocations_offset_;
    uint32_t nbof_relocations_;
    //! @brief `flags_` attribute holds both section's type and section's *flags*
    //!
    //! * Type:  `flags_[7:0]`
    //! * Flags: `flags_[31:8]`
    uint32_t flags_;
    uint32_t reserved1_;
    uint32_t reserved2_;
    uint32_t reserved3_;
    std::vector<uint8_t> content_;
    //! @brief Pointer to the segment holding this section.
    SegmentCommand *segment_;
    relocations_t relocations_;
};

}
}
#endif
