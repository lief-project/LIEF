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

#include <spdlog/fmt/fmt.h>

#include "LIEF/PE/signature/x509.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"
#include "LIEF/PE/signature/SignerInfo.hpp"
#include "LIEF/PE/signature/Attribute.hpp"

#include "LIEF/PE/EnumToString.hpp"

namespace LIEF {
namespace PE {

SignerInfo::SignerInfo(void) = default;
SignerInfo::~SignerInfo(void) = default;

SignerInfo::SignerInfo(SignerInfo&&) = default;
SignerInfo& SignerInfo::operator=(SignerInfo&&) = default;

SignerInfo::SignerInfo(const SignerInfo& other) :
  Object::Object(other),
  version_{other.version_},
  issuer_{other.issuer_},
  serialno_{other.serialno_},
  digest_algorithm_{other.digest_algorithm_},
  digest_enc_algorithm_{other.digest_enc_algorithm_},
  encrypted_digest_{other.encrypted_digest_}
{
  for (const std::unique_ptr<Attribute>& attr : other.authenticated_attributes_) {
    this->authenticated_attributes_.push_back(attr->clone());
  }

  for (const std::unique_ptr<Attribute>& attr : other.unauthenticated_attributes_) {
    this->unauthenticated_attributes_.push_back(attr->clone());
  }

  if (other.cert_ != nullptr) {
    this->cert_ = std::unique_ptr<x509>(new x509{*other.cert_});
  }
}

SignerInfo& SignerInfo::operator=(SignerInfo other) {
  this->swap(other);
  return *this;
}

void SignerInfo::swap(SignerInfo& other) {
  std::swap(this->version_,                    other.version_);
  std::swap(this->issuer_,                     other.issuer_);
  std::swap(this->serialno_,                   other.serialno_);
  std::swap(this->digest_algorithm_,           other.digest_algorithm_);
  std::swap(this->digest_enc_algorithm_,       other.digest_enc_algorithm_);
  std::swap(this->encrypted_digest_,           other.encrypted_digest_);
  std::swap(this->authenticated_attributes_,   other.authenticated_attributes_);
  std::swap(this->unauthenticated_attributes_, other.unauthenticated_attributes_);
  std::swap(this->cert_,                       other.cert_);
}


uint32_t SignerInfo::version(void) const {
  return this->version_;
}

ALGORITHMS SignerInfo::digest_algorithm(void) const {
  return this->digest_algorithm_;
}

ALGORITHMS SignerInfo::encryption_algorithm(void) const {
  return this->digest_enc_algorithm_;
}

const SignerInfo::encrypted_digest_t& SignerInfo::encrypted_digest(void) const {
  return this->encrypted_digest_;
}

it_const_attributes_t SignerInfo::authenticated_attributes() const {
  std::vector<Attribute*> attrs(this->authenticated_attributes_.size(), nullptr);
  for (size_t i = 0; i < this->authenticated_attributes_.size(); ++i) {
    attrs[i] = this->authenticated_attributes_[i].get();
  }
  return attrs;
}

it_const_attributes_t SignerInfo::unauthenticated_attributes() const {
  std::vector<Attribute*> attrs(this->unauthenticated_attributes_.size(), nullptr);
  for (size_t i = 0; i < this->unauthenticated_attributes_.size(); ++i) {
    attrs[i] = this->unauthenticated_attributes_[i].get();
  }
  return attrs;
}


const Attribute* SignerInfo::get_attribute(PE::SIG_ATTRIBUTE_TYPES type) const {
  // First look for the attribute in the authenticated ones
  auto it_auth = std::find_if(std::begin(this->authenticated_attributes_), std::end(this->authenticated_attributes_),
      [type] (const std::unique_ptr<Attribute>& attr) {
        return attr->type() == type;
      });
  if (it_auth != std::end(this->authenticated_attributes_)) {
    return it_auth->get();
  }

  // Then in the UN-authenticated ones
  auto it_uauth = std::find_if(std::begin(this->unauthenticated_attributes_), std::end(this->unauthenticated_attributes_),
      [type] (const std::unique_ptr<Attribute>& attr) {
        return attr->type() == type;
      });
  if (it_uauth != std::end(this->unauthenticated_attributes_)) {
    return it_uauth->get();
  }

  // ... not found -> return nullptr
  return nullptr;
}

void SignerInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


std::ostream& operator<<(std::ostream& os, const SignerInfo& signer_info) {
  os << fmt::format("{}/{} - {} - {:d} auth attr - {:d} unauth attr",
      to_string(signer_info.digest_algorithm()),
      to_string(signer_info.encryption_algorithm()),
      signer_info.issuer(),
      signer_info.authenticated_attributes().size(),
      signer_info.unauthenticated_attributes().size());
  return os;
}

}
}
