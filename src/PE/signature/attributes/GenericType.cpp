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
#include "LIEF/PE/signature/attributes/GenericType.hpp"
namespace LIEF {
namespace PE {

GenericType::GenericType() :
  Attribute(SIG_ATTRIBUTE_TYPES::GENERIC_TYPE)
{}

GenericType::GenericType(const GenericType&) = default;
GenericType& GenericType::operator=(const GenericType&) = default;

std::unique_ptr<Attribute> GenericType::clone() const {
  return std::unique_ptr<Attribute>(new GenericType{*this});
}

GenericType::GenericType(oid_t oid, std::vector<uint8_t> raw) :
  Attribute(SIG_ATTRIBUTE_TYPES::GENERIC_TYPE),
  oid_{std::move(oid)},
  raw_{std::move(raw)}
{}

void GenericType::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string GenericType::print() const {
  return oid() + " (" + std::to_string(raw_content().size()) + " bytes)";
}


GenericType::~GenericType() = default;

}
}
