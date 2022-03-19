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
#include "LIEF/ART/Header.hpp"

#include <iomanip>

#include "LIEF/ART/EnumToString.hpp"
#include "LIEF/ART/hash.hpp"

namespace LIEF {
namespace ART {

Header::Header(const Header&) = default;
Header& Header::operator=(const Header&) = default;

Header::Header() = default;

Header::magic_t Header::magic() const { return magic_; }

art_version_t Header::version() const { return version_; }

uint32_t Header::image_begin() const { return image_begin_; }

uint32_t Header::image_size() const { return image_size_; }

uint32_t Header::oat_checksum() const { return oat_checksum_; }

uint32_t Header::oat_file_begin() const { return oat_file_begin_; }

uint32_t Header::oat_file_end() const { return oat_file_end_; }

uint32_t Header::oat_data_begin() const { return oat_data_begin_; }

uint32_t Header::oat_data_end() const { return oat_data_end_; }

int32_t Header::patch_delta() const { return patch_delta_; }

uint32_t Header::image_roots() const { return image_roots_; }

uint32_t Header::pointer_size() const { return pointer_size_; }

bool Header::compile_pic() const { return compile_pic_; }

uint32_t Header::nb_sections() const { return nb_sections_; }

uint32_t Header::nb_methods() const { return nb_methods_; }

uint32_t Header::boot_image_begin() const { return boot_image_begin_; }

uint32_t Header::boot_image_size() const { return boot_image_size_; }

uint32_t Header::boot_oat_begin() const { return boot_oat_begin_; }

uint32_t Header::boot_oat_size() const { return boot_oat_size_; }

STORAGE_MODES Header::storage_mode() const { return storage_mode_; }

uint32_t Header::data_size() const { return data_size_; }

void Header::accept(Visitor& visitor) const { visitor.visit(*this); }

bool Header::operator==(const Header& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Header::operator!=(const Header& rhs) const { return !(*this == rhs); }

std::ostream& operator<<(std::ostream& os, const Header& hdr) {
  static constexpr size_t WIDTH = 33;
  os << std::hex << std::left << std::showbase;
  os << std::setw(WIDTH) << std::setfill(' ') << "Magic: " << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ') << "Version: " << std::dec
     << hdr.version() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Image Begin: " << std::hex
     << hdr.image_begin() << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ') << "Image Size: " << std::hex
     << hdr.image_size() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Checksum: " << std::hex
     << hdr.oat_checksum() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "OAT File Begin: " << std::hex
     << hdr.oat_file_begin() << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ') << "OAT File End:" << std::hex
     << hdr.oat_file_end() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "OAT Data Begin: " << std::hex
     << hdr.oat_data_begin() << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ') << "OAT Data End:" << std::hex
     << hdr.oat_data_end() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Patch Delta:" << std::dec
     << hdr.patch_delta() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Pointer Size:" << std::dec
     << hdr.pointer_size() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ')
     << "Compile pic:" << std::boolalpha << hdr.compile_pic() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ')
     << "Number of sections:" << std::dec << hdr.nb_sections() << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ')
     << "Number of methods:" << std::dec << hdr.nb_methods() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Boot Image Begin:" << std::hex
     << hdr.boot_image_begin() << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ') << "Boot Image Size:" << std::hex
     << hdr.boot_image_size() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Boot OAT Begin:" << std::hex
     << hdr.boot_oat_begin() << std::endl;
  os << std::setw(WIDTH) << std::setfill(' ') << "Boot OAT Size:" << std::hex
     << hdr.boot_oat_size() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ')
     << "Storage Mode:" << to_string(hdr.storage_mode()) << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Data Size:" << std::hex
     << hdr.data_size() << std::endl;

  return os;
}

Header::~Header() = default;

}  // Namespace ART
}  // Namespace LIEF
