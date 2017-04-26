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
#ifndef LIEF_ELF_SECTION_H_
#define LIEF_ELF_SECTION_H_

#include <string>
#include <vector>
#include <iostream>
#include <tuple>
#include <set>

#include "LIEF/visibility.h"

#include "LIEF/Abstract/Section.hpp"

#include "LIEF/ELF/type_traits.hpp"
#include "LIEF/ELF/Structures.hpp"
#include "LIEF/ELF/DataHandler/Handler.hpp"


namespace LIEF {
namespace ELF {

class Segment;
class Parser;
class Binary;

//! @brief Class wich represent sections
class DLL_PUBLIC Section : public LIEF::Section {

  friend class Parser;
  friend class Binary;

 public:
    Section(uint8_t *data, ELF_CLASS type);
    Section(const Elf64_Shdr* header);
    Section(const Elf32_Shdr* header);

    Section(void);
    ~Section(void);

    Section& operator=(Section other);
    Section(const Section& other);
    void swap(Section& other);

    uint32_t                  name_idx(void) const;
    SECTION_TYPES type(void) const;

    // ============================
    // LIEF::Section implementation
    // ============================

    //! @brief Section's content
    virtual std::vector<uint8_t> content(void) const override;

    //! @brief Set section content
    virtual void content(const std::vector<uint8_t>& data) override;

    //! @brief Section flags LIEF::ELF::SECTION_FLAGS
    uint64_t flags(void) const;

    //! @brief ``True`` if the section has the given flag
    //!
    //! @param[in] flag flag to test
    bool has_flag(SECTION_FLAGS flag) const;

    //! @brief Return section flags as a ``std::set``
    std::set<SECTION_FLAGS> flags_list(void) const;

    //! @see offset
    uint64_t file_offset(void) const;
    uint64_t original_size(void) const;
    uint64_t alignment(void) const;
    uint64_t information(void) const;
    uint64_t entry_size(void) const;
    uint32_t link(void) const;


    void type(SECTION_TYPES type);
    void flags(uint64_t flags);
    void add_flag(SECTION_FLAGS flag);
    void remove_flag(SECTION_FLAGS flag);
    void clear_flags(void);
    void file_offset(uint64_t offset);
    void link(uint32_t link);
    void information(uint32_t info);
    void alignment(uint64_t alignment);
    void entry_size(uint64_t entry_size);

    it_segments       segments(void);
    it_const_segments segments(void) const;

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const Section& rhs) const;
    bool operator!=(const Section& rhs) const;

    DLL_PUBLIC friend std::ostream& operator<<(std::ostream& os, const Section& section);

  private:

    // virtualAddress_, offset_ and size_ are inherited from LIEF::Section
    uint32_t              name_idx_;
    SECTION_TYPES         type_;
    uint64_t              flags_;
    uint64_t              original_size_;
    uint32_t              link_;
    uint32_t              info_;
    uint64_t              address_align_;
    uint64_t              entry_size_;
    segments_t            segments_;
    DataHandler::Handler* datahandler_;
    std::vector<uint8_t>  content_c_;



};

}
}
#endif /* _ELF_SECTION_H_ */
