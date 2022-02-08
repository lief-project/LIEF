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
#include <utility>

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/ResourceData.hpp"

namespace LIEF {
namespace PE {
ResourceData::~ResourceData() = default;
ResourceData& ResourceData::operator=(ResourceData other) {
  swap(other);
  return *this;
}

ResourceData::ResourceData(const ResourceData& other) :
  ResourceNode{static_cast<const ResourceNode&>(other)},
  content_{other.content_},
  code_page_{other.code_page_},
  reserved_{other.reserved_}
{}

ResourceData* ResourceData::clone() const {
  return new ResourceData{*this};
}

void ResourceData::swap(ResourceData& other) {
  ResourceNode::swap(other);

  std::swap(content_,    other.content_);
  std::swap(code_page_,  other.code_page_);
  std::swap(reserved_,   other.reserved_);
}


ResourceData::ResourceData() {
  type_ = ResourceNode::TYPE::DATA;
}


ResourceData::ResourceData(std::vector<uint8_t> content, uint32_t code_page) :
  content_{std::move(content)},
  code_page_{code_page}
{
  type_ = ResourceNode::TYPE::DATA;
}



uint32_t ResourceData::code_page() const {
  return code_page_;
}


const std::vector<uint8_t>& ResourceData::content() const {
  return content_;
}


uint32_t ResourceData::reserved() const {
  return reserved_;
}

uint32_t ResourceData::offset() const {
  return offset_;
}


void ResourceData::code_page(uint32_t code_page) {
  code_page_ = code_page;
}


void ResourceData::content(const std::vector<uint8_t>& content) {
  content_ = content;
}


void ResourceData::reserved(uint32_t value) {
  reserved_ = value;
}

void ResourceData::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceData::operator==(const ResourceData& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceData::operator!=(const ResourceData& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const ResourceData& data) {
  os << static_cast<const ResourceNode&>(data) << std::endl;
  os << "    " << std::setw(13) << std::left << std::setfill(' ') << "Code page :" << data.code_page()                       << std::endl;
  os << "    " << std::setw(13) << std::left << std::setfill(' ') << "Reserved :"  << data.reserved()                        << std::endl;
  os << "    " << std::setw(13) << std::left << std::setfill(' ') << "Size :"      << data.content().size()                  << std::endl;
  os << "    " << std::setw(13) << std::left << std::setfill(' ') << "Hash :"      << std::hex << Hash::hash(data.content()) << std::endl;
  return os;
}


}
}
