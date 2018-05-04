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

#include "LIEF/exception.hpp"

#include "LIEF/PE/hash.hpp"

#include "LIEF/utils.hpp"
#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include "LIEF/PE/resources/LangCodeItem.hpp"

namespace LIEF {
namespace PE {

LangCodeItem::LangCodeItem(const LangCodeItem&) = default;
LangCodeItem& LangCodeItem::operator=(const LangCodeItem&) = default;
LangCodeItem::~LangCodeItem(void) = default;


LangCodeItem::LangCodeItem(void) :
  type_{0},
  key_{u8tou16("040c04B0")}, // English standard
  items_{}
{}

uint16_t LangCodeItem::type(void) const {
  return this->type_;
}

const std::u16string& LangCodeItem::key(void) const {
  return this->key_;
}


CODE_PAGES LangCodeItem::code_page(void) const {
  if (this->key().length() != 8) {
    throw corrupted(std::string("'") + u16tou8(this->key()) + "': Wrong size");
  }

  return static_cast<CODE_PAGES>(std::stoul(u16tou8(this->key().substr(4, 8)), 0, 16));
}

RESOURCE_LANGS LangCodeItem::lang(void) const {
  if (this->key().length() != 8) {
    throw corrupted(std::string("'") + u16tou8(this->key()) + "': Wrong size");
  }

  uint64_t lang_id = std::stoul(u16tou8(this->key().substr(0, 4)), 0, 16);
  RESOURCE_LANGS lang = static_cast<RESOURCE_LANGS>(lang_id & 0x3ff);
  return lang;

}

RESOURCE_SUBLANGS LangCodeItem::sublang(void) const {
  if (this->key().length() != 8) {
    throw corrupted(std::string("'") + u16tou8(this->key()) + "': Wrong size");
  }

  uint64_t lang_id = std::stoul(u16tou8(this->key().substr(0, 4)), 0, 16);
  RESOURCE_SUBLANGS sublang = ResourcesManager::sub_lang(this->lang(), (lang_id >> 10));
  return sublang;
}


const std::map<std::u16string, std::u16string>& LangCodeItem::items(void) const {
  return this->items_;
}

std::map<std::u16string, std::u16string>& LangCodeItem::items(void) {
  return const_cast<std::map<std::u16string, std::u16string>&>(static_cast<const LangCodeItem*>(this)->items());
}


void LangCodeItem::type(uint16_t type) {
  this->type_ = type;
}

void LangCodeItem::key(const std::u16string& key) {
  this->key_ = key;
}

void LangCodeItem::key(const std::string& key) {
  this->key_ = u8tou16(key);
}

void LangCodeItem::code_page(CODE_PAGES code_page) {
  //TODO: Check
  std::stringstream ss;
  ss << std::setfill('0') << std::setw(sizeof(uint16_t) * 2) << std::hex << static_cast<uint16_t>(code_page);
  std::u16string cp = u8tou16(ss.str());
  std::u16string key = this->key();
  key.replace(4, 4, cp);
  this->key(key);

}

void LangCodeItem::lang(RESOURCE_LANGS lang) {
  //TODO: Check
  uint64_t lang_id = std::stoul(u16tou8(this->key().substr(0, 4)), 0, 16);
  lang_id &= ~static_cast<uint64_t>(0x3ff);
  lang_id |= static_cast<uint16_t>(lang);

  std::stringstream ss;
  ss << std::setfill('0') << std::setw(sizeof(uint16_t) * 2) << std::hex << static_cast<uint16_t>(lang_id);

  std::u16string langid = u8tou16(ss.str());
  std::u16string key = this->key();
  key.replace(0, 4, langid);
  this->key(key);

}

void LangCodeItem::sublang(RESOURCE_SUBLANGS lang) {
  //TODO: Check
  uint64_t lang_id = std::stoul(u16tou8(this->key().substr(0, 4)), 0, 16);
  uint64_t mask = (static_cast<uint64_t>(-1) >> 16) << 16;
  mask |= 0x3ff;

  lang_id &= mask;
  lang_id |= static_cast<uint16_t>(lang) << 10;

  std::stringstream ss;
  ss << std::setfill('0') << std::setw(sizeof(uint16_t) * 2) << std::hex << static_cast<uint16_t>(lang_id);

  std::u16string langid = u8tou16(ss.str());
  std::u16string key = this->key();
  key.replace(0, 4, langid);
  this->key(key);
}


void LangCodeItem::items(const std::map<std::u16string, std::u16string>& items) {
  this->items_ = items;
}


void LangCodeItem::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool LangCodeItem::operator==(const LangCodeItem& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool LangCodeItem::operator!=(const LangCodeItem& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const LangCodeItem& item) {
  os << std::hex << std::left;
  os << std::setw(8) << std::setfill(' ') << "type:" << item.type()         << std::endl;
  os << std::setw(8) << std::setfill(' ') << "key:"  << u16tou8(item.key())
     << ": ("
     << to_string(item.lang())
     << " - "
     <<  to_string(item.sublang())
     << " - "
     << std::hex << to_string(item.code_page()) << ")" << std::endl;
  os << std::setw(8) << std::setfill(' ') << "Items: " << std::endl;
  for (const std::pair<std::u16string, std::u16string>& p : item.items()) {
    os << "    " << "'" << u16tou8(p.first) << "': '" << u16tou8(p.second) << "'" << std::endl;
  }
  return os;
}


}
}
