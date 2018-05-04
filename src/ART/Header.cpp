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
#include "LIEF/ART/Header.hpp"
#include "LIEF/ART/hash.hpp"
#include "LIEF/ART/EnumToString.hpp"

#include <iomanip>

namespace LIEF {
namespace ART {

Header::Header(const Header&) = default;
Header& Header::operator=(const Header&) = default;

Header::Header(void) = default;

Header::magic_t Header::magic(void) const {
  return this->magic_;
}

art_version_t Header::version(void) const {
  return this->version_;
}

uint32_t Header::image_begin(void) const {
  return this->image_begin_;
}

uint32_t Header::image_size(void) const {
  return this->image_size_;
}

uint32_t Header::oat_checksum(void) const {
  return this->oat_checksum_;
}

uint32_t Header::oat_file_begin(void) const {
  return this->oat_file_begin_;
}

uint32_t Header::oat_file_end(void) const {
  return this->oat_file_end_;
}

uint32_t Header::oat_data_begin(void) const {
  return this->oat_data_begin_;
}

uint32_t Header::oat_data_end(void) const {
  return this->oat_data_end_;
}

int32_t Header::patch_delta(void) const {
  return this->patch_delta_;
}

uint32_t Header::image_roots(void) const {
  return this->image_roots_;
}

uint32_t Header::pointer_size(void) const {
  return this->pointer_size_;
}

bool Header::compile_pic(void) const {
  return this->compile_pic_;
}

uint32_t Header::nb_sections(void) const {
  return this->nb_sections_;
}

uint32_t Header::nb_methods(void) const {
  return this->nb_methods_;
}

uint32_t Header::boot_image_begin(void) const {
  return this->boot_image_begin_;
}

uint32_t Header::boot_image_size(void) const {
  return this->boot_image_size_;
}

uint32_t Header::boot_oat_begin(void) const {
  return this->boot_oat_begin_;
}

uint32_t Header::boot_oat_size(void) const {
  return this->boot_oat_size_;
}

STORAGE_MODES Header::storage_mode(void) const {
  return this->storage_mode_;
}

uint32_t Header::data_size(void) const {
  return this->data_size_;
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
  static constexpr size_t WIDTH = 33;
  os << std::hex << std::left << std::showbase;
  os << std::setw(WIDTH) << std::setfill(' ') << "Magic: " << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ') << "Version: " << std::dec << hdr.version() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Image Begin: " << std::hex << hdr.image_begin() << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ') << "Image Size: "  << std::hex << hdr.image_size() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Checksum: " << std::hex << hdr.oat_checksum() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "OAT File Begin: " << std::hex << hdr.oat_file_begin() << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ') << "OAT File End:"    << std::hex << hdr.oat_file_end() << std::endl;


  os << std::setw(WIDTH) << std::setfill(' ') << "OAT Data Begin: " << std::hex << hdr.oat_data_begin() << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ') << "OAT Data End:"    << std::hex << hdr.oat_data_end() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Patch Delta:"    << std::dec << hdr.patch_delta() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Pointer Size:"    << std::dec << hdr.pointer_size() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Compile pic:"    << std::boolalpha << hdr.compile_pic() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Number of sections:"    << std::dec << hdr.nb_sections() << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ') << "Number of methods:"    << std::dec << hdr.nb_methods() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Boot Image Begin:"  << std::hex << hdr.boot_image_begin() << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ') << "Boot Image Size:"    << std::hex << hdr.boot_image_size() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Boot OAT Begin:"  << std::hex << hdr.boot_oat_begin() << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ') << "Boot OAT Size:"   << std::hex << hdr.boot_oat_size() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Storage Mode:" << to_string(hdr.storage_mode()) << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Data Size:" << std::hex << hdr.data_size() << std::endl;

  return os;
}

Header::~Header(void) = default;

} // Namespace ART
} // Namespace LIEF

