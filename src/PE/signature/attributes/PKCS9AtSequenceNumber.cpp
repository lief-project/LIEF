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
#include "LIEF/PE/signature/attributes/PKCS9AtSequenceNumber.hpp"

namespace LIEF {
namespace PE {

PKCS9AtSequenceNumber::PKCS9AtSequenceNumber() :
  Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_AT_SEQUENCE_NUMBER)
{}

PKCS9AtSequenceNumber::PKCS9AtSequenceNumber(const PKCS9AtSequenceNumber&) = default;
PKCS9AtSequenceNumber& PKCS9AtSequenceNumber::operator=(const PKCS9AtSequenceNumber&) = default;

std::unique_ptr<Attribute> PKCS9AtSequenceNumber::clone() const {
  return std::unique_ptr<Attribute>(new PKCS9AtSequenceNumber{*this});
}

PKCS9AtSequenceNumber::PKCS9AtSequenceNumber(uint32_t num) :
  Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_AT_SEQUENCE_NUMBER),
  number_{num}
{}

void PKCS9AtSequenceNumber::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string PKCS9AtSequenceNumber::print() const {
  return std::to_string(number());
}


PKCS9AtSequenceNumber::~PKCS9AtSequenceNumber() = default;

}
}
