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

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/ResourceData.hpp"

namespace LIEF {
namespace PE {
ResourceData::~ResourceData(void) = default;
ResourceData& ResourceData::operator=(ResourceData other) {
  this->swap(other);
  return *this;
}

ResourceData::ResourceData(const ResourceData& other) :
  ResourceNode{static_cast<const ResourceNode&>(other)},
  content_{other.content_},
  code_page_{other.code_page_},
  reserved_{other.reserved_}
{}

ResourceData* ResourceData::clone(void) const {
  return new ResourceData{*this};
}

void ResourceData::swap(ResourceData& other) {
  ResourceNode::swap(other);

  std::swap(this->content_,    other.content_);
  std::swap(this->code_page_,  other.code_page_);
  std::swap(this->reserved_,   other.reserved_);
}


ResourceData::ResourceData(void) :
  content_{},
  code_page_{0},
  reserved_{0}
{}


ResourceData::ResourceData(const std::vector<uint8_t>& content, uint32_t code_page) :
  content_{content},
  code_page_{code_page},
  reserved_{0}
{}



uint32_t ResourceData::code_page(void) const {
  return this->code_page_;
}


const std::vector<uint8_t>& ResourceData::content(void) const {
  return this->content_;
}


uint32_t ResourceData::reserved(void) const {
  return this->reserved_;
}

uint32_t ResourceData::offset(void) const {
  return this->offset_;
}


void ResourceData::code_page(uint32_t code_page) {
  this->code_page_ = code_page;
}


void ResourceData::content(const std::vector<uint8_t>& content) {
  this->content_ = content;
}


void ResourceData::reserved(uint32_t value) {
  this->reserved_ = value;
}

void ResourceData::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceData::operator==(const ResourceData& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceData::operator!=(const ResourceData& rhs) const {
  return not (*this == rhs);
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
