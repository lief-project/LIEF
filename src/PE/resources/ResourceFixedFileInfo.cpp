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

#include "LIEF/PE/EnumToString.hpp"
#include "PE/Structures.hpp"

#include "LIEF/PE/resources/ResourceFixedFileInfo.hpp"

namespace LIEF {
namespace PE {

ResourceFixedFileInfo::ResourceFixedFileInfo(const ResourceFixedFileInfo&) = default;
ResourceFixedFileInfo& ResourceFixedFileInfo::operator=(const ResourceFixedFileInfo&) = default;
ResourceFixedFileInfo::~ResourceFixedFileInfo() = default;


ResourceFixedFileInfo::ResourceFixedFileInfo() :
  signature_{0xFEEF04BD},
  struct_version_{0},
  file_version_MS_{0},
  file_version_LS_{0},
  product_version_MS_{0},
  product_version_LS_{0},
  file_flags_mask_{0},
  file_flags_{0},
  file_os_{FIXED_VERSION_OS::VOS_UNKNOWN},
  file_type_{FIXED_VERSION_FILE_TYPES::VFT_UNKNOWN},
  file_subtype_{FIXED_VERSION_FILE_SUB_TYPES::VFT2_UNKNOWN},
  file_date_MS_{0},
  file_date_LS_{0}
{}


ResourceFixedFileInfo::ResourceFixedFileInfo(const details::pe_resource_fixed_file_info& header) :
  signature_{header.signature},
  struct_version_{header.struct_version},
  file_version_MS_{header.file_version_MS},
  file_version_LS_{header.file_version_LS},
  product_version_MS_{header.product_version_MS},
  product_version_LS_{header.product_version_LS},
  file_flags_mask_{header.file_flags_mask},
  file_flags_{header.file_flags},
  file_os_{static_cast<FIXED_VERSION_OS>(header.file_OS)},
  file_type_{static_cast<FIXED_VERSION_FILE_TYPES>(header.file_type)},
  file_subtype_{static_cast<FIXED_VERSION_FILE_SUB_TYPES>(header.file_subtype)},
  file_date_MS_{header.file_date_MS},
  file_date_LS_{header.file_date_LS}
{}


uint32_t ResourceFixedFileInfo::signature() const {
  return signature_;
}

uint32_t ResourceFixedFileInfo::struct_version() const {
  return struct_version_;
}

uint32_t ResourceFixedFileInfo::file_version_MS() const {
  return file_version_MS_;
}

uint32_t ResourceFixedFileInfo::file_version_LS() const {
  return file_version_LS_;
}

uint32_t ResourceFixedFileInfo::product_version_MS() const {
  return product_version_MS_;
}

uint32_t ResourceFixedFileInfo::product_version_LS() const {
  return product_version_LS_;
}

uint32_t ResourceFixedFileInfo::file_flags_mask() const {
  return file_flags_mask_;
}

uint32_t ResourceFixedFileInfo::file_flags() const {
  return file_flags_;
}

FIXED_VERSION_OS ResourceFixedFileInfo::file_os() const {
  return file_os_;
}

FIXED_VERSION_FILE_TYPES ResourceFixedFileInfo::file_type() const {
  return file_type_;
}

FIXED_VERSION_FILE_SUB_TYPES ResourceFixedFileInfo::file_subtype() const {
  return file_subtype_;
}

uint32_t ResourceFixedFileInfo::file_date_MS() const {
  return file_date_MS_;
}

uint32_t ResourceFixedFileInfo::file_date_LS() const {
  return file_date_LS_;
}

void ResourceFixedFileInfo::signature(uint32_t signature) {
  signature_ = signature;
}

void ResourceFixedFileInfo::struct_version(uint32_t struct_version) {
  struct_version_ = struct_version;
}

void ResourceFixedFileInfo::file_version_MS(uint32_t file_version_MS) {
  file_version_MS_ = file_version_MS;
}

void ResourceFixedFileInfo::file_version_LS(uint32_t file_version_LS) {
  file_version_LS_ = file_version_LS;
}

void ResourceFixedFileInfo::product_version_MS(uint32_t product_version_MS) {
  product_version_MS_ = product_version_MS;
}

void ResourceFixedFileInfo::product_version_LS(uint32_t product_version_LS) {
  product_version_LS_ = product_version_LS;
}

void ResourceFixedFileInfo::file_flags_mask(uint32_t file_flags_mask) {
  file_flags_mask_ = file_flags_mask;
}

void ResourceFixedFileInfo::file_flags(uint32_t file_flags) {
  file_flags_ = file_flags;
}

void ResourceFixedFileInfo::file_os(FIXED_VERSION_OS file_os) {
  file_os_ = file_os;
}

void ResourceFixedFileInfo::file_type(FIXED_VERSION_FILE_TYPES file_type) {
  file_type_ = file_type;
}

void ResourceFixedFileInfo::file_subtype(FIXED_VERSION_FILE_SUB_TYPES file_subtype) {
  file_subtype_ = file_subtype;
}

void ResourceFixedFileInfo::file_date_MS(uint32_t file_date_MS) {
  file_date_MS_ = file_date_MS;
}

void ResourceFixedFileInfo::file_date_LS(uint32_t file_date_LS) {
  file_date_LS_ = file_date_LS;
}

void ResourceFixedFileInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool ResourceFixedFileInfo::operator==(const ResourceFixedFileInfo& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceFixedFileInfo::operator!=(const ResourceFixedFileInfo& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const ResourceFixedFileInfo& fixed_info) {

  // File Version (readable)
  std::string file_version_str;
  file_version_str += std::to_string((fixed_info.file_version_MS() >> 16) & 0xFFFF);
  file_version_str += " - ";
  file_version_str += std::to_string(fixed_info.file_version_MS() & 0xFFFF);
  file_version_str += " - ";
  file_version_str += std::to_string((fixed_info.file_version_LS() >> 16) & 0xFFFF);
  file_version_str += " - ";
  file_version_str += std::to_string(fixed_info.file_version_LS() & 0xFFFF);

  // Product Version (readable)
  std::string product_version_str;
  product_version_str += std::to_string((fixed_info.product_version_MS() >> 16) & 0xFFFF);
  product_version_str += " - ";
  product_version_str += std::to_string(fixed_info.product_version_MS() & 0xFFFF);
  product_version_str += " - ";
  product_version_str += std::to_string((fixed_info.product_version_LS() >> 16) & 0xFFFF);
  product_version_str += " - ";
  product_version_str += std::to_string(fixed_info.product_version_LS() & 0xFFFF);

  os << std::hex << std::left;
  os << std::setw(17) << std::setfill(' ') << "Signature:"       << fixed_info.signature()            << std::endl;
  os << std::setw(17) << std::setfill(' ') << "Struct version:"  << fixed_info.struct_version()       << std::endl;
  os << std::setw(17) << std::setfill(' ') << "File version:"    << file_version_str                  << std::endl;
  os << std::setw(17) << std::setfill(' ') << "Product version:" << product_version_str               << std::endl;
  os << std::setw(17) << std::setfill(' ') << "File OS:"         << to_string(fixed_info.file_os())   << std::endl;
  os << std::setw(17) << std::setfill(' ') << "File type:"       << to_string(fixed_info.file_type()) << std::endl;
  if (fixed_info.file_type() == FIXED_VERSION_FILE_TYPES::VFT_DRV ||
      fixed_info.file_type() == FIXED_VERSION_FILE_TYPES::VFT_FONT) {
    os << std::setw(17) << std::setfill(' ') << "File sub-type:" << to_string(fixed_info.file_subtype()) << std::endl;
  }
  return os;
}


}
}
