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
#include <sstream>
#include <numeric>

#include "LIEF/PE/hash.hpp"

#include "LIEF/utils.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include "LIEF/PE/ResourcesManager.hpp"
#include "LIEF/PE/resources/ResourceVarFileInfo.hpp"

namespace LIEF {
namespace PE {

ResourceVarFileInfo::ResourceVarFileInfo(const ResourceVarFileInfo&) = default;
ResourceVarFileInfo& ResourceVarFileInfo::operator=(const ResourceVarFileInfo&) = default;
ResourceVarFileInfo::~ResourceVarFileInfo() = default;


ResourceVarFileInfo::ResourceVarFileInfo(uint16_t type, std::u16string key) :
  type_{type},
  key_{std::move(key)}
{}

ResourceVarFileInfo::ResourceVarFileInfo() :
  key_{u8tou16("VarFileInfo")}
{}


uint16_t ResourceVarFileInfo::type() const {
  return type_;
}

const std::u16string& ResourceVarFileInfo::key() const {
  return key_;
}

const std::vector<uint32_t>& ResourceVarFileInfo::translations() const {
  return translations_;
}

void ResourceVarFileInfo::type(uint16_t type) {
  type_ = type;
}

void ResourceVarFileInfo::key(const std::u16string& key) {
  key_ = key;
}

void ResourceVarFileInfo::key(const std::string& key) {
  this->key(u8tou16(key));
}

std::vector<uint32_t>& ResourceVarFileInfo::translations() {
  return const_cast<std::vector<uint32_t>&>(static_cast<const ResourceVarFileInfo*>(this)->translations());
}

void ResourceVarFileInfo::translations(const std::vector<uint32_t>& translations) {
  translations_ = translations;
}

void ResourceVarFileInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool ResourceVarFileInfo::operator==(const ResourceVarFileInfo& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceVarFileInfo::operator!=(const ResourceVarFileInfo& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const ResourceVarFileInfo& entry) {

  std::string translation_str = std::accumulate(
     std::begin(entry.translations()), std::end(entry.translations()), std::string{},
     [] (const std::string& a, uint32_t t) {
       std::stringstream ss;
       uint16_t lsb = t & 0xFFFF;
       uint16_t msb = t >> 16;
       auto cp = static_cast<CODE_PAGES>(msb);

       auto lang = static_cast<RESOURCE_LANGS>(lsb & 0x3ff);
       RESOURCE_SUBLANGS sublang = ResourcesManager::sub_lang(lang, (lsb >> 10));

       ss << to_string(cp) << "/" << to_string(lang) << "/" << to_string(sublang);
       return a.empty() ? ss.str() : a + " - " + ss.str();
     });

  os << std::hex << std::left;
  os << std::setw(14) << std::setfill(' ') << "type:"          << entry.type()         << std::endl;
  os << std::setw(14) << std::setfill(' ') << "key:"           << u16tou8(entry.key()) << std::endl;
  os << std::setw(14) << std::setfill(' ') << "Translations:"  << translation_str      << std::endl;

  return os;
}


}
}
