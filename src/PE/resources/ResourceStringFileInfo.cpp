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

#include "LIEF/PE/hash.hpp"

#include "LIEF/utils.hpp"

#include "LIEF/PE/resources/ResourceStringFileInfo.hpp"

namespace LIEF {
namespace PE {

ResourceStringFileInfo::ResourceStringFileInfo(const ResourceStringFileInfo&) = default;
ResourceStringFileInfo& ResourceStringFileInfo::operator=(const ResourceStringFileInfo&) = default;
ResourceStringFileInfo::~ResourceStringFileInfo() = default;

ResourceStringFileInfo::ResourceStringFileInfo(uint16_t type, std::u16string key) :
  type_{type},
  key_{std::move(key)}
{}

ResourceStringFileInfo::ResourceStringFileInfo() :
  key_{u8tou16("StringFileInfo")}
{}


uint16_t ResourceStringFileInfo::type() const {
  return type_;
}

const std::u16string& ResourceStringFileInfo::key() const {
  return key_;
}

const std::vector<LangCodeItem>& ResourceStringFileInfo::langcode_items() const {
  return childs_;
}

std::vector<LangCodeItem>& ResourceStringFileInfo::langcode_items() {
  return const_cast<std::vector<LangCodeItem>&>(static_cast<const ResourceStringFileInfo*>(this)->langcode_items());
}


void ResourceStringFileInfo::type(uint16_t type) {
  type_ = type;
}

void ResourceStringFileInfo::key(const std::u16string& key) {
  key_ = key;
}

void ResourceStringFileInfo::key(const std::string& key) {
  key_ = u8tou16(key);
}

void ResourceStringFileInfo::langcode_items(const std::vector<LangCodeItem>& items) {
  childs_ = items;
}


void ResourceStringFileInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool ResourceStringFileInfo::operator==(const ResourceStringFileInfo& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceStringFileInfo::operator!=(const ResourceStringFileInfo& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const ResourceStringFileInfo& string_file_info) {
  os << std::hex << std::left;
  os << std::setw(7) << std::setfill(' ') << "type: " << string_file_info.type()         << std::endl;
  os << std::setw(7) << std::setfill(' ') << "key: "  << u16tou8(string_file_info.key()) << std::endl << std::endl;

  for (const LangCodeItem& item : string_file_info.langcode_items()) {
    os << item << std::endl;
  }
  return os;
}


}
}
