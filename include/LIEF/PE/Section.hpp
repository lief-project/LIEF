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
#ifndef LIEF_PE_SECTION_H_
#define LIEF_PE_SECTION_H_
#include <iostream>
#include <vector>
#include <string>
#include <set>

#include "LIEF/visibility.h"

#include "LIEF/Abstract/Section.hpp"

#include "LIEF/PE/Structures.hpp"


namespace LIEF {
namespace PE {

class Parser;
class Builder;
class Binary;

class LIEF_API Section : public LIEF::Section {

  friend class Parser;
  friend class Builder;
  friend class Binary;

  public:
    using LIEF::Section::name;

    Section(const pe_section* header);
    Section(void);
    Section(const std::vector<uint8_t>& data, const std::string& name = "", uint32_t characteristics = 0);
    Section(const std::string& name);

    Section& operator=(const Section&);
    Section(const Section&);
    virtual ~Section(void);

    //! @brief Return the size of the data in the section.
    uint32_t sizeof_raw_data(void) const;
    uint32_t virtual_size(void) const;

    // ============================
    // LIEF::Section implementation
    // ============================
    virtual std::vector<uint8_t> content(void) const override;


    uint32_t pointerto_raw_data(void) const;
    uint32_t pointerto_relocation(void) const;
    uint32_t pointerto_line_numbers(void) const;
    uint16_t numberof_relocations(void) const;
    uint16_t numberof_line_numbers(void) const;
    uint32_t characteristics(void) const;

    bool                              is_type(PE_SECTION_TYPES type) const;
    const std::set<PE_SECTION_TYPES>& types(void) const;
    bool                              has_characteristic(SECTION_CHARACTERISTICS c) const;
    std::set<SECTION_CHARACTERISTICS> characteristics_list(void) const;


    virtual void name(const std::string& name) override;
    virtual void content(const std::vector<uint8_t>& data) override;
    void virtual_size(uint32_t virtualSize);
    void pointerto_raw_data(uint32_t pointerToRawData);
    void pointerto_relocation(uint32_t pointerToRelocation);
    void pointerto_line_numbers(uint32_t pointerToLineNumbers);
    void numberof_relocations(uint16_t numberOfRelocations);
    void numberof_line_numbers(uint16_t numberOfLineNumbers);
    void sizeof_raw_data(uint32_t sizeOfRawData);
    void characteristics(uint32_t characteristics);
    void type(PE_SECTION_TYPES type);
    void add_type(PE_SECTION_TYPES type);
    void remove_type(PE_SECTION_TYPES type);
    void add_characteristic(SECTION_CHARACTERISTICS characteristic);
    void remove_characteristic(SECTION_CHARACTERISTICS characteristic);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const Section& rhs) const;
    bool operator!=(const Section& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const Section& section);

  private:
    std::vector<uint8_t>& content_ref(void);

    uint32_t                virtualSize_;
    std::vector<uint8_t>    content_;
    uint32_t                pointerToRelocations_;
    uint32_t                pointerToLineNumbers_;
    uint16_t                numberOfRelocations_;
    uint16_t                numberOfLineNumbers_;
    uint32_t                characteristics_;
    std::set<PE_SECTION_TYPES> types_;
};

} // namespace PE
} // namespace LIEF
#endif /* _PE_SECTION_H_ */
