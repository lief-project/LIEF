/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 * Copyright 2020 K. Nakagawa
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

#include "LIEF/utils.hpp"
#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/signature/OIDDefinitions.h"
#include "LIEF/PE/signature/UnauthenticatedAttributes.hpp"
#include "LIEF/PE/signature/SignerInfo.hpp"
#include "LIEF/PE/signature/Signature.hpp"

namespace LIEF {
namespace PE {

UnauthenticatedAttributes::UnauthenticatedAttributes(void) = default;
UnauthenticatedAttributes::~UnauthenticatedAttributes(void) = default;

UnauthenticatedAttributes::UnauthenticatedAttributes(UnauthenticatedAttributes&& unauth) = default;
UnauthenticatedAttributes& UnauthenticatedAttributes::operator=(UnauthenticatedAttributes&& unauth) = default;

const oid_t& UnauthenticatedAttributes::content_type(void) const {
  return this->content_type_;
}

bool UnauthenticatedAttributes::is_nested_signature() const {
  return content_type_ == OID_MS_SPC_NESTED_SIGNATURE;
}

bool UnauthenticatedAttributes::is_counter_signature() const {
  return content_type_ == OID_COUNTER_SIGNATURE;
}

bool UnauthenticatedAttributes::is_timestamping_signature() const {
  return content_type_ == OID_MS_COUNTER_SIGN;
}

const Signature& UnauthenticatedAttributes::nested_signature() const {
  if (not is_nested_signature()) {
    throw not_found("UnauthenticatedAttributes does not have nested signature");
  }
  return *this->nested_signature_;
}

const SignerInfo& UnauthenticatedAttributes::counter_signature() const {
  if (not is_counter_signature()) {
    throw not_found("UnauthenticatedAttributes does not have nested signature");
  }
  return *this->counter_signature_;
}

const SignerInfo& UnauthenticatedAttributes::timestamping_signature() const {
  if (not is_timestamping_signature()) {
    throw not_found("UnauthenticatedAttributes does not have timestamping signature");
  }
  return *this->timestamping_signature_;
}

void UnauthenticatedAttributes::accept(Visitor &visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const UnauthenticatedAttributes& unauthenticated_attributes) {
  if (unauthenticated_attributes.is_nested_signature()) {
    os << "Nested signature" << std::endl;
    os << "================" << std::endl;
    os << unauthenticated_attributes.nested_signature();
    os << std::endl;
    return os;
  } else if (unauthenticated_attributes.is_counter_signature()) {
    os << "Counter signature" << std::endl;
    os << "=================" << std::endl;
    os << unauthenticated_attributes.counter_signature();
    os << std::endl;
    return os;
  } else if (unauthenticated_attributes.is_timestamping_signature()) {
    // TODO: to be implemented
    os << "Timestamping signature" << std::endl;
    os << "======================" << std::endl;
    // os << unauthenticated_attributes.timestamping_signature();
    os << std::endl;
    return os;
  }
  os << "Do not have nested/counter/timestamping signature" << std::endl;
  return os;
}

}
}
