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
#include <fstream>
#include <iterator>

#include "LIEF/exception.hpp"

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/resources/ResourceIcon.hpp"

namespace LIEF {
namespace PE {

ResourceIcon::ResourceIcon(const ResourceIcon&) = default;
ResourceIcon& ResourceIcon::operator=(const ResourceIcon&) = default;
ResourceIcon::~ResourceIcon(void) = default;

ResourceIcon::ResourceIcon(void) :
  width_{0},
  height_{0},
  color_count_{0},
  reserved_{0},
  planes_{0},
  bit_count_{0},
  id_{static_cast<uint32_t>(-1)},
  lang_{RESOURCE_LANGS::LANG_NEUTRAL},
  sublang_{RESOURCE_SUBLANGS::SUBLANG_DEFAULT},
  pixels_{}
{}


ResourceIcon::ResourceIcon(const pe_resource_icon_group *header) :
  width_{header->width},
  height_{header->height},
  color_count_{header->color_count},
  reserved_{header->reserved},
  planes_{header->planes},
  bit_count_{header->bit_count},
  id_{header->ID},
  lang_{RESOURCE_LANGS::LANG_NEUTRAL},
  sublang_{RESOURCE_SUBLANGS::SUBLANG_DEFAULT},
  pixels_{}
{}


ResourceIcon::ResourceIcon(const pe_icon_header *header) :
  width_{header->width},
  height_{header->height},
  color_count_{header->color_count},
  reserved_{header->reserved},
  planes_{header->planes},
  bit_count_{header->bit_count},
  id_{static_cast<uint32_t>(-1)},
  lang_{RESOURCE_LANGS::LANG_NEUTRAL},
  sublang_{RESOURCE_SUBLANGS::SUBLANG_DEFAULT},
  pixels_{}
{}


ResourceIcon::ResourceIcon(const std::string& iconpath) {
  std::ifstream file(iconpath, std::ios::in | std::ios::binary);

  std::vector<uint8_t> raw;
  if (file) {
    file.unsetf(std::ios::skipws);
    file.seekg(0, std::ios::end);
    uint64_t size = static_cast<uint64_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    raw.reserve(size);

    raw.insert(std::begin(raw),
               std::istream_iterator<uint8_t>(file),
               std::istream_iterator<uint8_t>());
  } else {
    throw LIEF::bad_file("Unable to open " + iconpath); // XXX: Not exception within a ctor
  }

  const pe_icon_header* icon_header = reinterpret_cast<const pe_icon_header*>(raw.data() + sizeof(pe_resource_icon_dir));
  new (this) ResourceIcon{icon_header};

  this->pixels_ = {std::begin(raw) + icon_header->offset, std::begin(raw) + icon_header->offset + icon_header->size};
}

uint32_t ResourceIcon::id(void) const {
  return this->id_;
}

RESOURCE_LANGS ResourceIcon::lang(void) const {
  return this->lang_;
}

RESOURCE_SUBLANGS ResourceIcon::sublang(void) const {
  return this->sublang_;
}

uint8_t ResourceIcon::width(void) const {
  return this->width_;
}

uint8_t ResourceIcon::height(void) const {
  return this->height_;
}

uint8_t ResourceIcon::color_count(void) const {
  return this->color_count_;
}

uint8_t ResourceIcon::reserved(void) const {
  return this->reserved_;
}

uint16_t ResourceIcon::planes(void) const {
  return this->planes_;
}

uint16_t ResourceIcon::bit_count(void) const {
  return this->bit_count_;
}

uint32_t ResourceIcon::size(void) const {
  return this->pixels_.size();
}

const std::vector<uint8_t>& ResourceIcon::pixels(void) const {
  return this->pixels_;
}

void ResourceIcon::id(uint32_t id) {
  this->id_ = id;
}

void ResourceIcon::lang(RESOURCE_LANGS lang) {
  this->lang_ = lang;
}

void ResourceIcon::sublang(RESOURCE_SUBLANGS sublang) {
  this->sublang_ = sublang;
}

void ResourceIcon::width(uint8_t width) {
  this->width_ = width;
}

void ResourceIcon::height(uint8_t height) {
  this->height_ = height;
}

void ResourceIcon::color_count(uint8_t color_count) {
  this->color_count_ = color_count;
}

void ResourceIcon::reserved(uint8_t reserved) {
  this->reserved_ = reserved;
}

void ResourceIcon::planes(uint16_t planes) {
  this->planes_ = planes;
}

void ResourceIcon::bit_count(uint16_t bit_count) {
  this->bit_count_ = bit_count;
}

void ResourceIcon::pixels(const std::vector<uint8_t>& pixels) {
  this->pixels_ = pixels;
}


void ResourceIcon::save(const std::string& filename) const {
  std::vector<uint8_t> icon(sizeof(pe_resource_icon_dir) + sizeof(pe_icon_header) + this->pixels_.size(), 0);
  pe_resource_icon_dir dir_header;
  dir_header.reserved = 0;
  dir_header.type     = 1;
  dir_header.count    = 1;

  pe_icon_header icon_header;
  icon_header.width       = static_cast<uint8_t>(this->width());
  icon_header.height      = static_cast<uint8_t>(this->height());
  icon_header.color_count = static_cast<uint8_t>(this->color_count());
  icon_header.reserved    = static_cast<uint8_t>(this->reserved());
  icon_header.planes      = static_cast<uint16_t>(this->planes());
  icon_header.bit_count   = static_cast<uint16_t>(this->bit_count());
  icon_header.size        = static_cast<uint32_t>(this->size());
  icon_header.offset      = sizeof(pe_resource_icon_dir) + sizeof(pe_icon_header);

  const std::vector<uint8_t>& pixels = this->pixels();

  std::copy(
      reinterpret_cast<const uint8_t*>(&dir_header),
      reinterpret_cast<const uint8_t*>(&dir_header) + sizeof(pe_resource_icon_dir),
      icon.data());

  std::copy(
      reinterpret_cast<const uint8_t*>(&icon_header),
      reinterpret_cast<const uint8_t*>(&icon_header) + sizeof(pe_icon_header),
      icon.data() + sizeof(pe_resource_icon_dir));

  std::copy(
      std::begin(pixels),
      std::end(pixels),
      icon.data() + sizeof(pe_resource_icon_dir) + sizeof(pe_icon_header));


  std::ofstream output_file{filename, std::ios::out | std::ios::binary | std::ios::trunc};
  if (output_file) {
    std::copy(
        std::begin(icon),
        std::end(icon),
        std::ostreambuf_iterator<char>(output_file));
  }
}

void ResourceIcon::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceIcon::operator==(const ResourceIcon& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceIcon::operator!=(const ResourceIcon& rhs) const {
  return not (*this == rhs);
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

