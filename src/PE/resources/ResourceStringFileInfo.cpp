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

#include "LIEF/Visitor.hpp"

#include "LIEF/utils.hpp"
#include "logging.hpp"

#include "LIEF/PE/resources/ResourceStringFileInfo.hpp"

namespace LIEF {
namespace PE {

ResourceStringFileInfo::ResourceStringFileInfo() :
  key_{*u8tou16("StringFileInfo")}
{}


void ResourceStringFileInfo::key(const std::string& key) {
  if (auto res = u8tou16(key)) {
    key_ = std::move(*res);
  } else {
    LIEF_WARN("{} can't be converted in a UTF-16 string", key);
  }
}

void ResourceStringFileInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const ResourceStringFileInfo& string_file_info) {
  os << std::hex << std::left;
  os << std::setw(7) << std::setfill(' ') << "type: " << string_file_info.type()         << '\n';
  os << std::setw(7) << std::setfill(' ') << "key: "  << u16tou8(string_file_info.key()) << '\n' << '\n';

  for (const LangCodeItem& item : string_file_info.langcode_items()) {
    os << item << '\n';
  }
  return os;
}


}
}
