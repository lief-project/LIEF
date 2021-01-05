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
#include <iomanip>
#include <numeric>
#include <iterator>

#include "LIEF/PE/hash.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/Abstract/Section.hpp"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/EnumToString.hpp"

namespace LIEF {
namespace PE {

Section::~Section(void) = default;

Section::Section(void) = default;


Section& Section::operator=(const Section&) = default;
Section::Section(const Section&) = default;

Section::Section(const pe_section* header) :
  virtual_size_{header->VirtualSize},
  pointer_to_relocations_{header->PointerToRelocations},
  pointer_to_linenumbers_{header->PointerToLineNumbers},
  number_of_relocations_{header->NumberOfRelocations},
  number_of_linenumbers_{header->NumberOfLineNumbers},
  characteristics_{header->Characteristics},
  types_{PE_SECTION_TYPES::UNKNOWN}
{
  this->name_            = std::string(header->Name, sizeof(header->Name)).c_str();
  this->virtual_address_ = header->VirtualAddress;
  this->size_            = header->SizeOfRawData;
  this->offset_          = header->PointerToRawData;
}

Section::Section(const std::vector<uint8_t>& data, const std::string& name, uint32_t characteristics) :
  Section::Section{}
{
  this->characteristics_ = characteristics;
  this->name_            = name;
  this->size_            = data.size();
  this->content_         = data;
}

Section::Section(const std::string& name) :
  Section::Section{}
{
  this->name_ = name;
}


uint32_t Section::virtual_size(void) const {
  return this->virtual_size_;
}



uint32_t Section::sizeof_raw_data(void) const {
  return this->size();
}

std::vector<uint8_t> Section::content(void) const {
  return this->content_;
}

std::vector<uint8_t>& Section::content_ref(void) {
  return this->content_;
}

uint32_t Section::pointerto_raw_data(void) const {
  return this->offset();
}


uint32_t Section::pointerto_relocation(void) const {
  return this->pointer_to_relocations_;
}


uint32_t Section::pointerto_line_numbers(void) const {
  return this->pointer_to_linenumbers_;
}

uint16_t Section::numberof_relocations(void) const {
  return this->number_of_relocations_;
}

uint16_t Section::numberof_line_numbers(void) const {
  return this->number_of_linenumbers_;
}

uint32_t Section::characteristics(void) const {
  return this->characteristics_;
}


const std::set<PE_SECTION_TYPES>& Section::types(void) const {
  return this->types_;
}


bool Section::is_type(PE_SECTION_TYPES type) const {
  return this->types_.count(type) != 0;
}


void Section::name(const std::string& name) {
  if (name.size() > STRUCT_SIZES::NameSize) {
    throw LIEF::pe_bad_section_name("Name is too big");
  }
  this->name_  = name;
}

bool Section::has_characteristic(SECTION_CHARACTERISTICS c) const {
  return (this->characteristics_ & static_cast<uint32_t>(c)) > 0;
}

std::set<SECTION_CHARACTERISTICS> Section::characteristics_list(void) const {
  std::set<SECTION_CHARACTERISTICS> charac;
  std::copy_if(
      std::begin(section_characteristics_array),
      std::end(section_characteristics_array),
      std::inserter(charac, std::begin(charac)),
      std::bind(&Section::has_characteristic, this, std::placeholders::_1));

  return charac;
}



void Section::content(const std::vector<uint8_t>& data) {
  this->content_ = data;
}


void Section::virtual_size(uint32_t virtualSize) {
  this->virtual_size_ = virtualSize;
}


void Section::pointerto_raw_data(uint32_t pointerToRawData) {
  this->offset(pointerToRawData);
}


void Section::pointerto_relocation(uint32_t pointerToRelocation) {
  this->pointer_to_relocations_ = pointerToRelocation;
}


void Section::pointerto_line_numbers(uint32_t pointerToLineNumbers) {
  this->pointer_to_linenumbers_ = pointerToLineNumbers;
}


void Section::numberof_relocations(uint16_t numberOfRelocations) {
  this->number_of_relocations_ = numberOfRelocations;
}


void Section::numberof_line_numbers(uint16_t numberOfLineNumbers) {
  this->number_of_linenumbers_ = numberOfLineNumbers;
}

void Section::sizeof_raw_data(uint32_t sizeOfRawData) {
  this->size(sizeOfRawData);
}


void Section::type(PE_SECTION_TYPES type) {
  this->types_ = {type};
}


void Section::remove_type(PE_SECTION_TYPES type) {
  this->types_.erase(type);
}


void Section::add_type(PE_SECTION_TYPES type) {
  this->types_.insert(type);
}


void Section::characteristics(uint32_t characteristics) {
  this->characteristics_ = characteristics;
}


void Section::remove_characteristic(SECTION_CHARACTERISTICS characteristic) {
  this->characteristics_ &= ~ static_cast<uint32_t>(characteristic);
}


void Section::add_characteristic(SECTION_CHARACTERISTICS characteristic) {
  this->characteristics_ |= static_cast<uint32_t>(characteristic);
}

void Section::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}


void Section::clear(uint8_t c) {
  std::fill(
      std::begin(this->content_),
      std::end(this->content_),
      c);
}

bool Section::operator==(const Section& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Section::operator!=(const Section& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const Section& section) {
  const auto& chara = section.characteristics_list();

  std::string chara_str = std::accumulate(
     std::begin(chara),
     std::end(chara), std::string{},
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
