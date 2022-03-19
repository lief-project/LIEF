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
#include "LIEF/PE/signature/SignerInfo.hpp"

#include <spdlog/fmt/fmt.h>

#include <iomanip>
#include <memory>
#include <numeric>
#include <sstream>
#include <type_traits>

#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/signature/Attribute.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"
#include "LIEF/PE/signature/x509.hpp"

namespace LIEF {
namespace PE {

SignerInfo::SignerInfo() = default;
SignerInfo::~SignerInfo() = default;

SignerInfo::SignerInfo(SignerInfo&&) = default;
SignerInfo& SignerInfo::operator=(SignerInfo&&) = default;

SignerInfo::SignerInfo(const SignerInfo& other)
    : Object::Object(other),
      version_{other.version_},
      issuer_{other.issuer_},
      serialno_{other.serialno_},
      digest_algorithm_{other.digest_algorithm_},
      digest_enc_algorithm_{other.digest_enc_algorithm_},
      encrypted_digest_{other.encrypted_digest_},
      raw_auth_data_{other.raw_auth_data_} {
  for (const std::unique_ptr<Attribute>& attr :
       other.authenticated_attributes_) {
    authenticated_attributes_.push_back(attr->clone());
  }

  for (const std::unique_ptr<Attribute>& attr :
       other.unauthenticated_attributes_) {
    unauthenticated_attributes_.push_back(attr->clone());
  }

  if (other.cert_ != nullptr) {
    cert_ = std::make_unique<x509>(*other.cert_);
  }
}

SignerInfo& SignerInfo::operator=(SignerInfo other) {
  swap(other);
  return *this;
}

void SignerInfo::swap(SignerInfo& other) {
  std::swap(version_, other.version_);
  std::swap(issuer_, other.issuer_);
  std::swap(serialno_, other.serialno_);
  std::swap(digest_algorithm_, other.digest_algorithm_);
  std::swap(digest_enc_algorithm_, other.digest_enc_algorithm_);
  std::swap(encrypted_digest_, other.encrypted_digest_);
  std::swap(raw_auth_data_, other.raw_auth_data_);
  std::swap(authenticated_attributes_, other.authenticated_attributes_);
  std::swap(unauthenticated_attributes_, other.unauthenticated_attributes_);
  std::swap(cert_, other.cert_);
}

uint32_t SignerInfo::version() const { return version_; }

ALGORITHMS SignerInfo::digest_algorithm() const { return digest_algorithm_; }

ALGORITHMS SignerInfo::encryption_algorithm() const {
  return digest_enc_algorithm_;
}

const SignerInfo::encrypted_digest_t& SignerInfo::encrypted_digest() const {
  return encrypted_digest_;
}

SignerInfo::it_const_attributes_t SignerInfo::authenticated_attributes() const {
  return authenticated_attributes_;
}

SignerInfo::it_const_attributes_t SignerInfo::unauthenticated_attributes()
    const {
  return unauthenticated_attributes_;
}

const Attribute* SignerInfo::get_attribute(PE::SIG_ATTRIBUTE_TYPES type) const {
  const Attribute* attr = get_auth_attribute(type);
  if (attr != nullptr) {
    return attr;
  }

  attr = get_unauth_attribute(type);

  if (attr != nullptr) {
    return attr;
  }

  // ... not found -> return nullptr
  return nullptr;
}

const Attribute* SignerInfo::get_auth_attribute(
    PE::SIG_ATTRIBUTE_TYPES type) const {
  auto it_auth = std::find_if(std::begin(authenticated_attributes_),
                              std::end(authenticated_attributes_),
                              [type](const std::unique_ptr<Attribute>& attr) {
                                return attr->type() == type;
                              });
  if (it_auth != std::end(authenticated_attributes_)) {
    return it_auth->get();
  }
  return nullptr;
}

const Attribute* SignerInfo::get_unauth_attribute(
    PE::SIG_ATTRIBUTE_TYPES type) const {
  auto it_uauth = std::find_if(std::begin(unauthenticated_attributes_),
                               std::end(unauthenticated_attributes_),
                               [type](const std::unique_ptr<Attribute>& attr) {
                                 return attr->type() == type;
                               });
  if (it_uauth != std::end(unauthenticated_attributes_)) {
    return it_uauth->get();
  }
  return nullptr;
}

void SignerInfo::accept(Visitor& visitor) const { visitor.visit(*this); }

std::ostream& operator<<(std::ostream& os, const SignerInfo& signer_info) {
  os << fmt::format("{}/{} - {} - {:d} auth attr - {:d} unauth attr",
                    to_string(signer_info.digest_algorithm()),
                    to_string(signer_info.encryption_algorithm()),
                    signer_info.issuer(),
                    signer_info.authenticated_attributes().size(),
                    signer_info.unauthenticated_attributes().size());
  return os;
}

}  // namespace PE
}  // namespace LIEF
