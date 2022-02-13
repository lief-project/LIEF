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
#include <iomanip>
#include <numeric>
#include <iterator>

#include "logging.hpp"
#include "LIEF/PE/hash.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/Abstract/Section.hpp"

#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

Section::~Section() = default;

Section::Section() = default;


Section& Section::operator=(const Section&) = default;
Section::Section(const Section&) = default;

Section::Section(const details::pe_section& header) :
  virtual_size_{header.VirtualSize},
  pointer_to_relocations_{header.PointerToRelocations},
  pointer_to_linenumbers_{header.PointerToLineNumbers},
  number_of_relocations_{header.NumberOfRelocations},
  number_of_linenumbers_{header.NumberOfLineNumbers},
  characteristics_{header.Characteristics}
{
  name_            = std::string(header.Name, sizeof(header.Name));
  virtual_address_ = header.VirtualAddress;
  size_            = header.SizeOfRawData;
  offset_          = header.PointerToRawData;
}

Section::Section(const std::vector<uint8_t>& data, const std::string& name, uint32_t characteristics) :
  Section::Section{}
{
  characteristics_ = characteristics;
  name_            = name;
  size_            = data.size();
  content_         = data;
}

Section::Section(const std::string& name) :
  Section::Section{}
{
  name_ = name;
}


uint32_t Section::virtual_size() const {
  return virtual_size_;
}

uint32_t Section::sizeof_raw_data() const {
  return size();
}

span<const uint8_t> Section::content() const {
  return content_;
}


uint32_t Section::pointerto_raw_data() const {
  return offset();
}


uint32_t Section::pointerto_relocation() const {
  return pointer_to_relocations_;
}


uint32_t Section::pointerto_line_numbers() const {
  return pointer_to_linenumbers_;
}

uint16_t Section::numberof_relocations() const {
  return number_of_relocations_;
}

uint16_t Section::numberof_line_numbers() const {
  return number_of_linenumbers_;
}

uint32_t Section::characteristics() const {
  return characteristics_;
}


const std::set<PE_SECTION_TYPES>& Section::types() const {
  return types_;
}


bool Section::is_type(PE_SECTION_TYPES type) const {
  return types_.count(type) != 0;
}


void Section::name(const std::string& name) {
  if (name.size() > details::STRUCT_SIZES::NameSize) {
    LIEF_ERR("The max size of a section's name is {} vs {d}",
             details::STRUCT_SIZES::NameSize, name.size());
    return;
  }
  name_ = name;
}

bool Section::has_characteristic(SECTION_CHARACTERISTICS c) const {
  return (characteristics_ & static_cast<uint32_t>(c)) > 0;
}

std::set<SECTION_CHARACTERISTICS> Section::characteristics_list() const {
  std::set<SECTION_CHARACTERISTICS> charac;
  std::copy_if(
      std::begin(details::section_characteristics_array), std::end(details::section_characteristics_array),
      std::inserter(charac, std::begin(charac)),
      [this] (SECTION_CHARACTERISTICS f) { return has_characteristic(f); });

  return charac;
}



void Section::content(const std::vector<uint8_t>& data) {
  content_ = data;
}


void Section::virtual_size(uint32_t virtualSize) {
  virtual_size_ = virtualSize;
}


void Section::pointerto_raw_data(uint32_t pointerToRawData) {
  offset(pointerToRawData);
}


void Section::pointerto_relocation(uint32_t pointerToRelocation) {
  pointer_to_relocations_ = pointerToRelocation;
}


void Section::pointerto_line_numbers(uint32_t pointerToLineNumbers) {
  pointer_to_linenumbers_ = pointerToLineNumbers;
}


void Section::numberof_relocations(uint16_t numberOfRelocations) {
  number_of_relocations_ = numberOfRelocations;
}


void Section::numberof_line_numbers(uint16_t numberOfLineNumbers) {
  number_of_linenumbers_ = numberOfLineNumbers;
}

void Section::sizeof_raw_data(uint32_t sizeOfRawData) {
  size(sizeOfRawData);
}


void Section::type(PE_SECTION_TYPES type) {
  types_ = {type};
}


void Section::remove_type(PE_SECTION_TYPES type) {
  types_.erase(type);
}


void Section::add_type(PE_SECTION_TYPES type) {
  types_.insert(type);
}


void Section::characteristics(uint32_t characteristics) {
  characteristics_ = characteristics;
}


void Section::remove_characteristic(SECTION_CHARACTERISTICS characteristic) {
  characteristics_ &= ~ static_cast<uint32_t>(characteristic);
}


void Section::add_characteristic(SECTION_CHARACTERISTICS characteristic) {
  characteristics_ |= static_cast<uint32_t>(characteristic);
}

void Section::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}


void Section::clear(uint8_t c) {
  std::fill(std::begin(content_), std::end(content_), c);
}

bool Section::operator==(const Section& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Section::operator!=(const Section& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const Section& section) {
  const auto& chara = section.characteristics_list();

  std::string chara_str = std::accumulate(
     std::begin(chara), std::end(chara), std::string{},
     [] (const std::string& a, SECTION_CHARACTERISTICS b) {
         return a.empty() ?
         to_string(b) :
         a + " - " + to_string(b);
     });
  os << std::hex;
  os << std::left
     << std::setw(10) << section.name()
     << std::setw(10) << section.virtual_size()
     << std::setw(10) << section.virtual_address()
     << std::setw(10) << section.size()
     << std::setw(10) << section.offset()
     << std::setw(10) << section.pointerto_relocation()
     << std::setw(10) << section.entropy()
     << std::setw(10) << chara_str;

  return os;
}

}
}
