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

#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"

namespace LIEF {
namespace PE {

Signature::Signature(void) = default; // TODO
Signature::Signature(const Signature&) = default;
Signature& Signature::operator=(const Signature&) = default;
Signature::~Signature(void) = default;

uint32_t Signature::version(void) const {
  return this->version_;
}

const oid_t& Signature::digest_algorithm(void) const {
  return this->digest_algorithm_;
}

const ContentInfo& Signature::content_info(void) const {
  return this->content_info_;
}

it_const_crt Signature::certificates(void) const {
  return {this->certificates_};
}

const SignerInfo& Signature::signer_info(void) const {
  return this->signer_info_;
}

const std::vector<uint8_t>& Signature::original_signature(void) const {
  return this->original_raw_signature_;
}

void Signature::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const Signature& signature) {
  constexpr uint8_t wsize = 30;
  os << std::hex << std::left;
  os << std::setw(wsize) << std::setfill(' ') << "Version: "          << signature.version() << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Digest Algorithm: " << oid_to_string(signature.digest_algorithm()) << std::endl;

  os << "Content Info" << std::endl;
  os << "============" << std::endl;
  os << signature.content_info() << std::endl << std::endl;


  os << "Certificates" << std::endl;
  os << "============" << std::endl;
  for (const x509& crt : signature.certificates()) {
    os << crt << std::endl;;
  }
  os << std::endl;

  os << "Signer Info" << std::endl;
  os << "===========" << std::endl;
  os << signature.signer_info() << std::endl << std::endl;

  return os;
}


}
}
