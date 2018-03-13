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
#ifndef LIEF_ELF_SEGMENT_H_
#define LIEF_ELF_SEGMENT_H_

#include <string>
#include <vector>
#include <iostream>
#include <memory>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/ELF/type_traits.hpp"
#include "LIEF/ELF/Structures.hpp"
#include "LIEF/ELF/Section.hpp"

namespace LIEF {
namespace ELF {

class Parser;
class Binary;

//! @brief Class which represent segments
class LIEF_API Segment : public Object {

  friend class Parser;
  friend class Section;
  friend class Binary;

  public:
    Segment(void);
    Segment(const std::vector<uint8_t>&   header, ELF_CLASS type);
    Segment(const std::vector<uint8_t>&   header);
    Segment(const Elf64_Phdr* header);
    Segment(const Elf32_Phdr* header);
    virtual ~Segment(void);

    Segment& operator=(Segment other);
    Segment(const Segment& other);
    void swap(Segment& other);

    SEGMENT_TYPES type(void) const;
    ELF_SEGMENT_FLAGS flags(void) const;
    uint64_t file_offset(void) const;
    uint64_t virtual_address(void) const;
    uint64_t physical_address(void) const;
    uint64_t physical_size(void) const;
    uint64_t virtual_size(void) const;
    uint64_t alignment(void) const;
    std::vector<uint8_t> content(void) const;

    bool has(ELF_SEGMENT_FLAGS flag) const;
    bool has(const Section& section) const;
    bool has(const std::string& section_name) const;

    void add(ELF_SEGMENT_FLAGS c);
    void remove(ELF_SEGMENT_FLAGS c);

    void type(SEGMENT_TYPES type);
    void flags(ELF_SEGMENT_FLAGS flags);
    void clear_flags(void);
    void file_offset(uint64_t fileOffset);
    void virtual_address(uint64_t virtualAddress);
    void physical_address(uint64_t physicalAddress);
    void physical_size(uint64_t physicalSize);
    void virtual_size(uint64_t virtualSize);
    void alignment(uint64_t alignment);
    void content(const std::vector<uint8_t>& content);
    void content(std::vector<uint8_t>&& content);

    it_sections       sections(void);
    it_const_sections sections(void) const;

    virtual void accept(Visitor& visitor) const override;

    Segment& operator+=(ELF_SEGMENT_FLAGS c);
    Segment& operator-=(ELF_SEGMENT_FLAGS c);

    bool operator==(const Segment& rhs) const;
    bool operator!=(const Segment& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const Segment& segment);

  private:
    SEGMENT_TYPES         type_;
    ELF_SEGMENT_FLAGS     flags_;
    uint64_t              file_offset_;
    uint64_t              virtual_address_;
    uint64_t              physical_address_;
    uint64_t              size_;
    uint64_t              virtual_size_;
    uint64_t              alignment_;
    sections_t            sections_;
    DataHandler::Handler* datahandler_;
    std::vector<uint8_t>  content_c_;
};


}
}
#endif /* _ELF_SEGMENT_H_ */
