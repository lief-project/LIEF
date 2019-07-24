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
#include <type_traits>
#include <numeric>
#include <sstream>

#include "LIEF/PE/signature/OIDToString.hpp"
#include "LIEF/PE/signature/SignerInfo.hpp"

namespace LIEF {
namespace PE {

SignerInfo::SignerInfo(void) = default;
SignerInfo::SignerInfo(const SignerInfo&) = default;
SignerInfo& SignerInfo::operator=(const SignerInfo&) = default;
SignerInfo::~SignerInfo(void) = default;


uint32_t SignerInfo::version(void) const {
  return this->version_;
}


const issuer_t& SignerInfo::issuer(void) const {
  return this->issuer_;
}


const oid_t& SignerInfo::digest_algorithm(void) const {
  return this->digest_algorithm_;
}


const AuthenticatedAttributes& SignerInfo::authenticated_attributes(void) const {
  return this->authenticated_attributes_;
}


const oid_t& SignerInfo::signature_algorithm(void) const {
  return this->signature_algorithm_;
}


const std::vector<uint8_t>& SignerInfo::encrypted_digest(void) const {
  return this->encrypted_digest_;
}

void SignerInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


std::ostream& operator<<(std::ostream& os, const SignerInfo& signer_info) {

  constexpr uint8_t wsize = 30;
  const issuer_t& issuer = signer_info.issuer();
  std::string issuer_str = std::get<0>(issuer);

  const std::vector<uint8_t>& sn = std::get<1>(issuer);;
  std::string sn_str = std::accumulate(
      std::begin(sn),
      std::end(sn),
      std::string(""),
      [] (std::string lhs, uint8_t x) {
        std::stringstream ss;
        ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint32_t>(x);
        return lhs.empty() ? ss.str() : lhs + ":" + ss.str();
      });


  os << std::hex << std::left;

  os << std::setw(wsize) << std::setfill(' ') << "Version: "             << signer_info.version() << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Serial Number: "       << sn_str << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Issuer DN: "           << issuer_str << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Digest Algorithm: "    << oid_to_string(signer_info.digest_algorithm()) << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Signature algorithm: " << oid_to_string(signer_info.signature_algorithm()) << std::endl;

  os << signer_info.authenticated_attributes() << std::endl;

  return os;
}

}
}
