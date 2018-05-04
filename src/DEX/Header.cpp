
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
#include "LIEF/DEX/Header.hpp"
#include "LIEF/DEX/hash.hpp"
#include "LIEF/utils.hpp"

#include <numeric>
#include <sstream>
#include <iomanip>

#define PRINT_FIELD(name,attr) \
  os << std::setw(WIDTH) << std::setfill(' ') << name << std::hex << attr << std::endl

#define PRINT_LOCATION(name,attr)                                               \
  os << std::setw(WIDTH) << std::setfill(' ') << name << std::hex << attr.first \
     << std::dec << " (#" << attr.second << ")" << std::endl

namespace LIEF {
namespace DEX {

Header::Header(const Header&) = default;
Header& Header::operator=(const Header&) = default;

Header::Header(void) {
}


magic_t Header::magic(void) const {
  return this->magic_;
}
uint32_t Header::checksum(void) const {
  return this->checksum_;
}
signature_t Header::signature(void) const {
  return this->signature_;
}

uint32_t Header::file_size(void) const {
  return this->file_size_;
}

uint32_t Header::header_size(void) const {
  return this->header_size_;
}

uint32_t Header::endian_tag(void) const {
  return this->endian_tag_;
}

uint32_t Header::nb_classes(void) const {
  return this->class_defs_size_;
}

uint32_t Header::nb_methods(void) const {
  return this->method_ids_size_;
}

uint32_t Header::map(void) const {
  return this->map_off_;
}

Header::location_t Header::strings(void) const {
  return {this->string_ids_off_, this->string_ids_size_};
}

Header::location_t Header::link(void) const {
  return {this->link_off_, this->link_size_};
}

Header::location_t Header::types(void) const {
  return {this->type_ids_off_, this->type_ids_size_};
}

Header::location_t Header::prototypes(void) const {
  return {this->proto_ids_off_, this->proto_ids_size_};
}

Header::location_t Header::fields(void) const {
  return {this->field_ids_off_, this->field_ids_size_};
}

Header::location_t Header::methods(void) const {
  return {this->method_ids_off_, this->method_ids_size_};
}

Header::location_t Header::classes(void) const {
  return {this->class_defs_off_, this->class_defs_size_};
}

Header::location_t Header::data(void) const {
  return {this->data_off_, this->data_size_};
}


void Header::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Header::operator==(const Header& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Header::operator!=(const Header& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const Header& hdr) {
  static constexpr size_t WIDTH = 20;

  std::string magic_str;
  for (uint8_t c : hdr.magic()) {
    if (::isprint(c)) {
      magic_str.push_back(static_cast<char>(c));
    } else {
      std::stringstream ss;
      ss << std::dec << "'\\" << static_cast<uint32_t>(c) << "'";
      magic_str += ss.str();
    }
  }

  const signature_t& sig = hdr.signature();
  std::string sig_str = std::accumulate(
      std::begin(sig),
      std::end(sig),
      std::string{},
      [] (const std::string& s, uint8_t c) {
        std::stringstream ss;
        return s + hex_str(c);
      });


  os << std::hex << std::left << std::showbase;
  PRINT_FIELD("Magic:",       magic_str);
  PRINT_FIELD("Checksum:",    hdr.checksum());
  PRINT_FIELD("Signature:",   sig_str);
  PRINT_FIELD("File Size:",   hdr.file_size());
  PRINT_FIELD("Header Size:", hdr.header_size());
  PRINT_FIELD("Endian Tag:",  hdr.endian_tag());
  PRINT_FIELD("Map Offset:",  hdr.map());

  PRINT_LOCATION("Strings:",     hdr.strings());
  PRINT_LOCATION("Link:",        hdr.link());
  PRINT_LOCATION("Types:",       hdr.types());
  PRINT_LOCATION("Prototypes:",  hdr.prototypes());
  PRINT_LOCATION("Fields:",      hdr.fields());
  PRINT_LOCATION("Methods:",     hdr.methods());
  PRINT_LOCATION("Classes:",     hdr.classes());
  PRINT_LOCATION("Data:",        hdr.data());

  return os;
}

Header::~Header(void) = default;



} // Namespace DEX
} // Namespace LIEF

