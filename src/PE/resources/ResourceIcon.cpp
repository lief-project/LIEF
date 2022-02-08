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
#include <fstream>
#include <iterator>

#include "LIEF/exception.hpp"

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/resources/ResourceIcon.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

ResourceIcon::ResourceIcon(const ResourceIcon&) = default;
ResourceIcon& ResourceIcon::operator=(const ResourceIcon&) = default;
ResourceIcon::~ResourceIcon() = default;

ResourceIcon::ResourceIcon() = default;

ResourceIcon::ResourceIcon(const details::pe_resource_icon_group& header) :
  width_{header.width},
  height_{header.height},
  color_count_{header.color_count},
  reserved_{header.reserved},
  planes_{header.planes},
  bit_count_{header.bit_count},
  id_{header.ID}
{}


ResourceIcon::ResourceIcon(const details::pe_icon_header& header) :
  width_{header.width},
  height_{header.height},
  color_count_{header.color_count},
  reserved_{header.reserved},
  planes_{header.planes},
  bit_count_{header.bit_count},
  id_{static_cast<uint32_t>(-1)}
{}


uint32_t ResourceIcon::id() const {
  return id_;
}

RESOURCE_LANGS ResourceIcon::lang() const {
  return lang_;
}

RESOURCE_SUBLANGS ResourceIcon::sublang() const {
  return sublang_;
}

uint8_t ResourceIcon::width() const {
  return width_;
}

uint8_t ResourceIcon::height() const {
  return height_;
}

uint8_t ResourceIcon::color_count() const {
  return color_count_;
}

uint8_t ResourceIcon::reserved() const {
  return reserved_;
}

uint16_t ResourceIcon::planes() const {
  return planes_;
}

uint16_t ResourceIcon::bit_count() const {
  return bit_count_;
}

uint32_t ResourceIcon::size() const {
  return pixels_.size();
}

const std::vector<uint8_t>& ResourceIcon::pixels() const {
  return pixels_;
}

void ResourceIcon::id(uint32_t id) {
  id_ = id;
}

void ResourceIcon::lang(RESOURCE_LANGS lang) {
  lang_ = lang;
}

void ResourceIcon::sublang(RESOURCE_SUBLANGS sublang) {
  sublang_ = sublang;
}

void ResourceIcon::width(uint8_t width) {
  width_ = width;
}

void ResourceIcon::height(uint8_t height) {
  height_ = height;
}

void ResourceIcon::color_count(uint8_t color_count) {
  color_count_ = color_count;
}

void ResourceIcon::reserved(uint8_t reserved) {
  reserved_ = reserved;
}

void ResourceIcon::planes(uint16_t planes) {
  planes_ = planes;
}

void ResourceIcon::bit_count(uint16_t bit_count) {
  bit_count_ = bit_count;
}

void ResourceIcon::pixels(const std::vector<uint8_t>& pixels) {
  pixels_ = pixels;
}


void ResourceIcon::save(const std::string& filename) const {
  std::vector<uint8_t> icon(sizeof(details::pe_resource_icon_dir) + sizeof(details::pe_icon_header) + pixels_.size(), 0);
  details::pe_resource_icon_dir dir_header;
  dir_header.reserved = 0;
  dir_header.type     = 1;
  dir_header.count    = 1;

  details::pe_icon_header icon_header;
  icon_header.width       = static_cast<uint8_t>(width());
  icon_header.height      = static_cast<uint8_t>(height());
  icon_header.color_count = static_cast<uint8_t>(color_count());
  icon_header.reserved    = static_cast<uint8_t>(reserved());
  icon_header.planes      = static_cast<uint16_t>(planes());
  icon_header.bit_count   = static_cast<uint16_t>(bit_count());
  icon_header.size        = static_cast<uint32_t>(size());
  icon_header.offset      = sizeof(details::pe_resource_icon_dir) + sizeof(details::pe_icon_header);

  const std::vector<uint8_t>& pixels = this->pixels();

  std::copy(
      reinterpret_cast<const uint8_t*>(&dir_header),
      reinterpret_cast<const uint8_t*>(&dir_header) + sizeof(details::pe_resource_icon_dir),
      icon.data());

  std::copy(
      reinterpret_cast<const uint8_t*>(&icon_header),
      reinterpret_cast<const uint8_t*>(&icon_header) + sizeof(details::pe_icon_header),
      icon.data() + sizeof(details::pe_resource_icon_dir));

  std::copy(
      std::begin(pixels),
      std::end(pixels),
      icon.data() + sizeof(details::pe_resource_icon_dir) + sizeof(details::pe_icon_header));


  std::ofstream output_file{filename, std::ios::out | std::ios::binary | std::ios::trunc};
  if (output_file) {
    std::copy(std::begin(icon), std::end(icon),
              std::ostreambuf_iterator<char>(output_file));
  }
}

void ResourceIcon::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceIcon::operator==(const ResourceIcon& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceIcon::operator!=(const ResourceIcon& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const ResourceIcon& icon) {
  os << std::setw(33) << std::left << std::setfill(' ') << "ID: "          << std::hex << icon.id()                                                                                       << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Size: "        << std::dec << static_cast<uint32_t>(icon.width()) << "x" << static_cast<uint32_t>(icon.height()) << " pixels" << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Color count: " << std::hex << static_cast<uint32_t>(icon.color_count())                                                       << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Reserved: "    << std::hex << static_cast<uint32_t>(icon.reserved())                                                          << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Planes: "      << std::hex << static_cast<uint32_t>(icon.planes())                                                            << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Bit count: "   << std::hex << static_cast<uint32_t>(icon.bit_count())                                                         << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Hash: "        << std::hex << Hash::hash(icon.pixels())                                                                       << std::endl;
  return os;
}



}
}

