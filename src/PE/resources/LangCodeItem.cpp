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

#include "logging.hpp"

#include "LIEF/PE/hash.hpp"

#include "LIEF/utils.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include "LIEF/PE/resources/LangCodeItem.hpp"
#include "LIEF/PE/ResourcesManager.hpp"

namespace LIEF {
namespace PE {

LangCodeItem::LangCodeItem() :
  key_{*u8tou16("040c04B0")}
{}

CODE_PAGES LangCodeItem::code_page() const {
  if (key().length() != 8) {
    LIEF_WARN("{} is expected to be 8 lengthy", u16tou8(key()));
    return static_cast<CODE_PAGES>(0);
  }

  return static_cast<CODE_PAGES>(std::stoul(u16tou8(key().substr(4, 8)), nullptr, 16));
}

uint32_t LangCodeItem::lang() const {
  if (key().length() != 8) {
    LIEF_WARN("{} is expected to be 8 lengthy", u16tou8(key()));
    return 0;
  }

  uint64_t lang_id = std::stoul(u16tou8(key().substr(0, 4)), nullptr, 16);
  return ResourcesManager::lang_from_id(lang_id);

}

uint32_t LangCodeItem::sublang() const {
  if (key().length() != 8) {
    LIEF_WARN("{} is expected to be 8 lengthy", u16tou8(key()));
    return 0;
  }

  uint64_t lang_id = std::stoul(u16tou8(key().substr(0, 4)), nullptr, 16);
  return ResourcesManager::sublang_from_id(lang_id);
}

void LangCodeItem::key(const std::string& key) {
  if (auto res = u8tou16(key)) {
    key_ = std::move(*res);
  } else {
    LIEF_WARN("{} can't be converted to a UTF-16 string", key);
  }
}

void LangCodeItem::code_page(CODE_PAGES code_page) {
  //TODO: Check
  std::stringstream ss;
  ss << std::setfill('0') << std::setw(sizeof(uint16_t) * 2) << std::hex << static_cast<uint16_t>(code_page);
  if (auto res = u8tou16(ss.str())) {
    std::u16string key = this->key();
    key.replace(4, 4, *res);
    this->key(key);
  } else {
    LIEF_WARN("Code page error");
  }
}

void LangCodeItem::lang(uint32_t lang) {
  uint64_t lang_id = std::stoul(u16tou8(key().substr(0, 4)), nullptr, 16);
  lang_id &= ~static_cast<uint64_t>(0x3ff);
  lang_id |= static_cast<uint16_t>(lang);

  std::stringstream ss;
  ss << std::setfill('0') << std::setw(sizeof(uint16_t) * 2) << std::hex << static_cast<uint16_t>(lang_id);

  if (auto res = u8tou16(ss.str())) {
    std::u16string key = this->key();
    key.replace(0, 4, *res);
    this->key(key);
  } else {
    LIEF_WARN("lang error");
  }
}

void LangCodeItem::sublang(uint32_t lang) {
  //TODO: Check
  uint64_t lang_id = std::stoul(u16tou8(key().substr(0, 4)), nullptr, 16);
  uint64_t mask = (static_cast<uint64_t>(-1) >> 16) << 16;
  mask |= 0x3ff;

  lang_id &= mask;
  lang_id |= static_cast<uint16_t>(lang) << 10;

  std::stringstream ss;
  ss << std::setfill('0') << std::setw(sizeof(uint16_t) * 2) << std::hex << static_cast<uint16_t>(lang_id);

  if (auto res = u8tou16(ss.str())) {
    std::u16string key = this->key();
    key.replace(0, 4, *res);
    this->key(key);
  } else {
    LIEF_WARN("lang error");
  }
}


void LangCodeItem::items(const LangCodeItem::items_t& items) {
  items_ = items;
}


void LangCodeItem::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const LangCodeItem& item) {
  os << std::hex << std::left;
  os << std::setw(8) << std::setfill(' ') << "type:" << item.type()         << '\n';
  os << std::setw(8) << std::setfill(' ') << "key:"  << u16tou8(item.key())
     << ": ("
     << item.lang()
     << " - "
     << item.sublang()
     << " - "
     << std::hex << to_string(item.code_page()) << ")" << '\n';
  os << std::setw(8) << std::setfill(' ') << "Items: " << '\n';
  for (const LangCodeItem::items_t::value_type& p : item.items()) {
    os << "    " << "'" << u16tou8(p.first) << "': '" << u16tou8(p.second) << "'" << '\n';
  }
  return os;
}


}
}
