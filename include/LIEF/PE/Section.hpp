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
#ifndef LIEF_PE_SECTION_H_
#define LIEF_PE_SECTION_H_
#include <iostream>
#include <vector>
#include <string>
#include <set>

#include "LIEF/visibility.h"
#include "LIEF/iterators.hpp"
#include "LIEF/Abstract/Section.hpp"
#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {

class Parser;
class Builder;
class Binary;

namespace details {
struct pe_section;
}

//! Class which represents a PE section
class LIEF_API Section : public LIEF::Section {

  friend class Parser;
  friend class Builder;
  friend class Binary;

  public:
  using LIEF::Section::name;

  Section(const details::pe_section& header);
  Section();
  Section(const std::vector<uint8_t>& data,
          const std::string& name = "", uint32_t characteristics = 0);
  Section(const std::string& name);

  Section& operator=(const Section&);
  Section(const Section&);
  ~Section() override;

  //! Return the size of the data in the section.
  uint32_t sizeof_raw_data() const;

  //! Return the size of the data when mapped in memory
  //!
  //! If this value is greater than sizeof_raw_data, the section is zero-padded.
  uint32_t virtual_size() const;

  //! The actual content of the section
  span<const uint8_t> content() const override;

  //! Content of the section's padding area
  inline const std::vector<uint8_t>& padding() const {
    return padding_;
  }

  //! The offset of the section data in the PE file
  uint32_t pointerto_raw_data() const;

  //! The file pointer to the beginning of the COFF relocation entries for the section. This is set to zero for
  //! executable images or if there are no relocations.
  //!
  //! For modern PE binaries, this value is usually set to 0 as the relocations are managed by
  //! PE::Relocation.
  uint32_t pointerto_relocation() const;

  //! The file pointer to the beginning of line-number entries for the section.
  //! This is set to zero if there are no COFF line numbers. This value should be zero for an image because COFF
  //! debugging information is deprecated and modern debug information relies on the PDB files.
  uint32_t pointerto_line_numbers() const;

  //! No longer used in recent PE binaries produced by Visual Studio
  uint16_t numberof_relocations() const;

  //! No longer used in recent PE binaries produced by Visual Studio
  uint16_t numberof_line_numbers() const;

  //! Characteristics of the section: it gives information about
  //! the permissions of the section when mapped. It can also provides
  //! information about the *purpose* of the section (contain code, BSS-like, ...)
  uint32_t characteristics() const;

  //! Deprecated do not use. It will likely change in a future release of LIEF
  bool is_type(PE_SECTION_TYPES type) const;

  //! Deprecated do not use. It will likely change in a future release of LIEF
  const std::set<PE_SECTION_TYPES>& types() const;

  //! Check if the section has the given SECTION_CHARACTERISTICS
  bool has_characteristic(SECTION_CHARACTERISTICS c) const;

  //! List of the section characteristics as a std::set
  std::set<SECTION_CHARACTERISTICS> characteristics_list() const;

  //! Fill the content of the section with the given ``char``
  void clear(uint8_t c);

  void name(const std::string& name) override;
  void content(const std::vector<uint8_t>& data) override;

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

  void accept(Visitor& visitor) const override;

  bool operator==(const Section& rhs) const;
  bool operator!=(const Section& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Section& section);

  private:
  inline span<uint8_t> writable_content() {
    return content_;
  }

  std::vector<uint8_t> content_;
  std::vector<uint8_t> padding_;
  uint32_t virtual_size_           = 0;
  uint32_t pointer_to_relocations_ = 0;
  uint32_t pointer_to_linenumbers_ = 0;
  uint16_t number_of_relocations_  = 0;
  uint16_t number_of_linenumbers_  = 0;
  uint32_t characteristics_        = 0;
  std::set<PE_SECTION_TYPES> types_ = {PE_SECTION_TYPES::UNKNOWN};
};

} // namespace PE
} // namespace LIEF
#endif /* _PE_SECTION_H_ */
