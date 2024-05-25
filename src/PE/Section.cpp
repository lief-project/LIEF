/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include <algorithm>
#include <iterator>

#include "logging.hpp"
#include "LIEF/Visitor.hpp"

#include "LIEF/PE/Section.hpp"
#include "PE/Structures.hpp"
#include "frozen.hpp"
#include <spdlog/fmt/fmt.h>

namespace LIEF {
namespace PE {

static constexpr std::array CHARACTERISTICS_LIST = {
  Section::CHARACTERISTICS::TYPE_NO_PAD,
  Section::CHARACTERISTICS::CNT_CODE,
  Section::CHARACTERISTICS::CNT_INITIALIZED_DATA,
  Section::CHARACTERISTICS::CNT_UNINITIALIZED_DATA,
  Section::CHARACTERISTICS::LNK_OTHER,
  Section::CHARACTERISTICS::LNK_INFO,
  Section::CHARACTERISTICS::LNK_REMOVE,
  Section::CHARACTERISTICS::LNK_COMDAT,
  Section::CHARACTERISTICS::GPREL,
  Section::CHARACTERISTICS::MEM_PURGEABLE,
  Section::CHARACTERISTICS::MEM_16BIT,
  Section::CHARACTERISTICS::MEM_LOCKED,
  Section::CHARACTERISTICS::MEM_PRELOAD,
  Section::CHARACTERISTICS::ALIGN_1BYTES,
  Section::CHARACTERISTICS::ALIGN_2BYTES,
  Section::CHARACTERISTICS::ALIGN_4BYTES,
  Section::CHARACTERISTICS::ALIGN_8BYTES,
  Section::CHARACTERISTICS::ALIGN_16BYTES,
  Section::CHARACTERISTICS::ALIGN_32BYTES,
  Section::CHARACTERISTICS::ALIGN_64BYTES,
  Section::CHARACTERISTICS::ALIGN_128BYTES,
  Section::CHARACTERISTICS::ALIGN_256BYTES,
  Section::CHARACTERISTICS::ALIGN_512BYTES,
  Section::CHARACTERISTICS::ALIGN_1024BYTES,
  Section::CHARACTERISTICS::ALIGN_2048BYTES,
  Section::CHARACTERISTICS::ALIGN_4096BYTES,
  Section::CHARACTERISTICS::ALIGN_8192BYTES,
  Section::CHARACTERISTICS::LNK_NRELOC_OVFL,
  Section::CHARACTERISTICS::MEM_DISCARDABLE,
  Section::CHARACTERISTICS::MEM_NOT_CACHED,
  Section::CHARACTERISTICS::MEM_NOT_PAGED,
  Section::CHARACTERISTICS::MEM_SHARED,
  Section::CHARACTERISTICS::MEM_EXECUTE,
  Section::CHARACTERISTICS::MEM_READ,
  Section::CHARACTERISTICS::MEM_WRITE,
};

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

Section::Section(const std::vector<uint8_t>& data, const std::string& name,
                 uint32_t characteristics) :
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

uint32_t Section::sizeof_raw_data() const {
  return size();
}

uint32_t Section::pointerto_raw_data() const {
  return offset();
}

const std::set<PE_SECTION_TYPES>& Section::types() const {
  return types_;
}

bool Section::is_type(PE_SECTION_TYPES type) const {
  return types_.count(type) != 0;
}

void Section::name(std::string name) {
  if (name.size() > MAX_SECTION_NAME) {
    LIEF_ERR("The max size of a section's name is {} vs {}", MAX_SECTION_NAME,
             name.size());
    return;
  }
  name_ = std::move(name);
}

std::vector<Section::CHARACTERISTICS> Section::characteristics_list() const {
  std::vector<Section::CHARACTERISTICS> list;
  list.reserve(3);
  std::copy_if(CHARACTERISTICS_LIST.begin(), CHARACTERISTICS_LIST.end(),
               std::back_inserter(list),
               [this] (CHARACTERISTICS c) { return has_characteristic(c); });

  return list;
}

void Section::content(const std::vector<uint8_t>& data) {
  content_ = data;
}

void Section::pointerto_raw_data(uint32_t pointerToRawData) {
  offset(pointerToRawData);
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

void Section::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

void Section::clear(uint8_t c) {
  std::fill(std::begin(content_), std::end(content_), c);
}

std::ostream& operator<<(std::ostream& os, const Section& section) {
  const auto& list = section.characteristics_list();
  std::vector<std::string> list_str;
  list_str.reserve(list.size());
  std::transform(list.begin(), list.end(), std::back_inserter(list_str),
                 [] (const auto c) { return to_string(c); });

  std::vector<std::string> fullname_hex;
  fullname_hex.reserve(section.name().size());
  std::transform(section.fullname().begin(), section.fullname().end(),
                 std::back_inserter(fullname_hex),
                 [] (const char c) { return fmt::format("{:02x}", c); });


  os << fmt::format("Name:                    {} ({})\n", section.name(), fmt::join(fullname_hex, " "))
     << fmt::format("Virtual size:            0x{:x}\n", section.virtual_size())
     << fmt::format("Virtual address:         0x{:x}\n", section.virtual_address())
     << fmt::format("Size of raw data:        0x{:x}\n", section.sizeof_raw_data())
     << fmt::format("Pointer to raw data:     0x{:x}\n", section.pointerto_raw_data())
     << fmt::format("Pointer to relocations:  0x{:x}\n", section.pointerto_relocation())
     << fmt::format("Pointer to line numbers: 0x{:x}\n", section.pointerto_line_numbers())
     << fmt::format("Number of relocations:   0x{:x}\n", section.numberof_relocations())
     << fmt::format("Number of lines:         0x{:x}\n", section.numberof_line_numbers())
     << fmt::format("Characteristics:         {}\n", fmt::join(list_str, ", "));
  return os;
}


const char* to_string(Section::CHARACTERISTICS e) {
  CONST_MAP(Section::CHARACTERISTICS, const char*, 35) enumStrings {
    { Section::CHARACTERISTICS::TYPE_NO_PAD,            "TYPE_NO_PAD" },
    { Section::CHARACTERISTICS::CNT_CODE,               "CNT_CODE" },
    { Section::CHARACTERISTICS::CNT_INITIALIZED_DATA,   "CNT_INITIALIZED_DATA" },
    { Section::CHARACTERISTICS::CNT_UNINITIALIZED_DATA, "CNT_UNINITIALIZED_DATA" },
    { Section::CHARACTERISTICS::LNK_OTHER,              "LNK_OTHER" },
    { Section::CHARACTERISTICS::LNK_INFO,               "LNK_INFO" },
    { Section::CHARACTERISTICS::LNK_REMOVE,             "LNK_REMOVE" },
    { Section::CHARACTERISTICS::LNK_COMDAT,             "LNK_COMDAT" },
    { Section::CHARACTERISTICS::GPREL,                  "GPREL" },
    { Section::CHARACTERISTICS::MEM_PURGEABLE,          "MEM_PURGEABLE" },
    { Section::CHARACTERISTICS::MEM_16BIT,              "MEM_16BIT" },
    { Section::CHARACTERISTICS::MEM_LOCKED,             "MEM_LOCKED" },
    { Section::CHARACTERISTICS::MEM_PRELOAD,            "MEM_PRELOAD" },
    { Section::CHARACTERISTICS::ALIGN_1BYTES,           "ALIGN_1BYTES" },
    { Section::CHARACTERISTICS::ALIGN_2BYTES,           "ALIGN_2BYTES" },
    { Section::CHARACTERISTICS::ALIGN_4BYTES,           "ALIGN_4BYTES" },
    { Section::CHARACTERISTICS::ALIGN_8BYTES,           "ALIGN_8BYTES" },
    { Section::CHARACTERISTICS::ALIGN_16BYTES,          "ALIGN_16BYTES" },
    { Section::CHARACTERISTICS::ALIGN_32BYTES,          "ALIGN_32BYTES" },
    { Section::CHARACTERISTICS::ALIGN_64BYTES,          "ALIGN_64BYTES" },
    { Section::CHARACTERISTICS::ALIGN_128BYTES,         "ALIGN_128BYTES" },
    { Section::CHARACTERISTICS::ALIGN_256BYTES,         "ALIGN_256BYTES" },
    { Section::CHARACTERISTICS::ALIGN_512BYTES,         "ALIGN_512BYTES" },
    { Section::CHARACTERISTICS::ALIGN_1024BYTES,        "ALIGN_1024BYTES" },
    { Section::CHARACTERISTICS::ALIGN_2048BYTES,        "ALIGN_2048BYTES" },
    { Section::CHARACTERISTICS::ALIGN_4096BYTES,        "ALIGN_4096BYTES" },
    { Section::CHARACTERISTICS::ALIGN_8192BYTES,        "ALIGN_8192BYTES" },
    { Section::CHARACTERISTICS::LNK_NRELOC_OVFL,        "LNK_NRELOC_OVFL" },
    { Section::CHARACTERISTICS::MEM_DISCARDABLE,        "MEM_DISCARDABLE" },
    { Section::CHARACTERISTICS::MEM_NOT_CACHED,         "MEM_NOT_CACHED" },
    { Section::CHARACTERISTICS::MEM_NOT_PAGED,          "MEM_NOT_PAGED" },
    { Section::CHARACTERISTICS::MEM_SHARED,             "MEM_SHARED" },
    { Section::CHARACTERISTICS::MEM_EXECUTE,            "MEM_EXECUTE" },
    { Section::CHARACTERISTICS::MEM_READ,               "MEM_READ" },
    { Section::CHARACTERISTICS::MEM_WRITE,              "MEM_WRITE" }
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNKNOWN" : it->second;
}

}
}
