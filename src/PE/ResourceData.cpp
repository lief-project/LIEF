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
#include "LIEF/visitors/Hash.hpp"

#include "LIEF/PE/ResourceData.hpp"

namespace LIEF {
namespace PE {
ResourceData::ResourceData(void) = default;
ResourceData::~ResourceData(void) = default;
ResourceData& ResourceData::operator=(const ResourceData&) = default;
ResourceData::ResourceData(const ResourceData&) = default;

ResourceData::ResourceData(const std::vector<uint8_t>& content, uint32_t codePage) :
  content_(content),
  codePage_(codePage)
{
  this->type_ = RESOURCE_NODE_TYPES::DATA;
}

uint32_t ResourceData::code_page(void) const {
  return this->codePage_;
}


const std::vector<uint8_t>& ResourceData::content(void) const {
  return this->content_;
}


void ResourceData::code_page(uint32_t codePage) {
  this->codePage_ = codePage;
}


void ResourceData::content(const std::vector<uint8_t>& content) {
  this->content_ = content;
}

void ResourceData::accept(Visitor& visitor) const {

  visitor.visit(this->code_page());
  visitor.visit(this->content());

}

bool ResourceData::operator==(const ResourceData& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceData::operator!=(const ResourceData& rhs) const {
  return not (*this == rhs);
}


}
}
