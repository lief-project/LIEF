/* Copyright 2021 - 2022 R. Thomas
 * Copyright 2021 - 2022 Quarkslab
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
#include "LIEF/PE/signature/attributes/ContentType.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"

namespace LIEF {
namespace PE {

ContentType::ContentType() :
  Attribute(SIG_ATTRIBUTE_TYPES::CONTENT_TYPE)
{}

ContentType::ContentType(const ContentType&) = default;
ContentType& ContentType::operator=(const ContentType&) = default;

std::unique_ptr<Attribute> ContentType::clone() const {
  return std::unique_ptr<Attribute>(new ContentType{*this});
}

ContentType::ContentType(oid_t oid) :
  Attribute(SIG_ATTRIBUTE_TYPES::CONTENT_TYPE),
  oid_{std::move(oid)}
{}

void ContentType::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string ContentType::print() const {
  return oid() + " (" + oid_to_string(oid()) + ")";
}


ContentType::~ContentType() = default;


}
}
