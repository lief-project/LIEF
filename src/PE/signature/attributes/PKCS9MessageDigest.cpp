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
#include "LIEF/PE/signature/attributes/PKCS9MessageDigest.hpp"
#include "LIEF/utils.hpp"

namespace LIEF {
namespace PE {

PKCS9MessageDigest::PKCS9MessageDigest() :
  Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_MESSAGE_DIGEST)
{}

PKCS9MessageDigest::PKCS9MessageDigest(const PKCS9MessageDigest&) = default;
PKCS9MessageDigest& PKCS9MessageDigest::operator=(const PKCS9MessageDigest&) = default;

PKCS9MessageDigest::PKCS9MessageDigest(std::vector<uint8_t> digest) :
  Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_MESSAGE_DIGEST),
  digest_{std::move(digest)}
{}

std::unique_ptr<Attribute> PKCS9MessageDigest::clone() const {
  return std::unique_ptr<Attribute>(new PKCS9MessageDigest{*this});
}


void PKCS9MessageDigest::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string PKCS9MessageDigest::print() const {
  return hex_dump(digest());
}


PKCS9MessageDigest::~PKCS9MessageDigest() = default;

}
}
