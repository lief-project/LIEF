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
#include <iomanip>
#include <sstream>
#include <numeric>

#include "LIEF/PE/hash.hpp"
#include "logging.hpp"

#include "LIEF/utils.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include "LIEF/PE/ResourcesManager.hpp"
#include "LIEF/PE/resources/ResourceVarFileInfo.hpp"

namespace LIEF {
namespace PE {

ResourceVarFileInfo::ResourceVarFileInfo(uint16_t type, std::u16string key) :
  type_{type},
  key_{std::move(key)}
{}

ResourceVarFileInfo::ResourceVarFileInfo() :
  key_{*u8tou16("VarFileInfo")}
{}


void ResourceVarFileInfo::key(const std::string& key) {
  if (auto res = u8tou16(key)) {
    return this->key(std::move(*res));
  }
  LIEF_WARN("{} can't be converted to a UTF-16 string", key);
}


void ResourceVarFileInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


std::ostream& operator<<(std::ostream& os, const ResourceVarFileInfo& entry) {
  std::string translation_str = std::accumulate(
     std::begin(entry.translations()), std::end(entry.translations()), std::string{},
     [] (const std::string& a, uint32_t t) {
       std::stringstream ss;
       uint16_t lsb = t & 0xFFFF;
       uint16_t msb = t >> 16;
       auto cp = static_cast<CODE_PAGES>(msb);

       uint32_t lang = ResourcesManager::lang_from_id(lsb);
       uint32_t sublang = ResourcesManager::sublang_from_id(lsb);

       ss << to_string(cp) << "/" << lang << "/" << sublang;
       return a.empty() ? ss.str() : a + " - " + ss.str();
     });

  os << std::hex << std::left;
  os << std::setw(14) << std::setfill(' ') << "type:"          << entry.type()         << '\n';
  os << std::setw(14) << std::setfill(' ') << "key:"           << u16tou8(entry.key()) << '\n';
  os << std::setw(14) << std::setfill(' ') << "Translations:"  << translation_str      << '\n';

  return os;
}


}
}
