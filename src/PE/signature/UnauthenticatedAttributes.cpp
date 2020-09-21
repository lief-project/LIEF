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

size_t UnauthenticatedAttributes::number_of_nested_signatures() const {
  return nested_signatures_.size();
}

size_t UnauthenticatedAttributes::number_of_counter_signatures() const {
  return counter_signatures_.size();
}

size_t UnauthenticatedAttributes::number_of_timestamping_signatures() const {
  return timestamping_signatures_.size();
}

bool UnauthenticatedAttributes::has_nested_signatures() const {
  return number_of_nested_signatures() != 0;
}

bool UnauthenticatedAttributes::has_counter_signatures() const {
  return number_of_counter_signatures() != 0;
}

bool UnauthenticatedAttributes::has_timestamping_signatures() const {
  return number_of_timestamping_signatures() != 0;
}

const Signature& UnauthenticatedAttributes::nested_signature(const size_t i) const {
  if (not has_nested_signatures()) {
    throw not_found("UnauthenticatedAttributes does not have a nested signature");
  }
  if (i >= nested_signatures_.size()) {
    throw not_found("index is out of bounds");
  }
  return *nested_signatures_[i];
}

const SignerInfo& UnauthenticatedAttributes::counter_signature(const size_t i) const {
  if (not has_counter_signatures()) {
    throw not_found("UnauthenticatedAttributes does not have a counter signature");
  }
  if (i >= counter_signatures_.size()) {
    throw not_found("index is out of bounds");
  }
  return *counter_signatures_[i];
}

const SignerInfo& UnauthenticatedAttributes::timestamping_signature(const size_t i) const {
  if (not has_timestamping_signatures()) {
    throw not_found("UnauthenticatedAttributes does not have a timestamping signature");
  }
  if (i >= timestamping_signatures_.size()) {
    throw not_found("index is out of bounds");
  }
  return *timestamping_signatures_[i];
}

const std::vector<std::unique_ptr<Signature>>& UnauthenticatedAttributes::nested_signatures() const {
  if (not has_nested_signatures()) {
    throw not_found("UnauthenticatedAttributes does not have nested signature");
  }
  return this->nested_signatures_;
}

const std::vector<std::unique_ptr<SignerInfo>>& UnauthenticatedAttributes::counter_signatures() const {
  if (not has_counter_signatures()) {
    throw not_found("UnauthenticatedAttributes does not have nested signature");
  }
  return this->counter_signatures_;
}

const std::vector<std::unique_ptr<SignerInfo>>& UnauthenticatedAttributes::timestamping_signatures() const {
  if (not has_timestamping_signatures()) {
    throw not_found("UnauthenticatedAttributes does not have timestamping signature");
  }
  return this->timestamping_signatures_;
}

void UnauthenticatedAttributes::accept(Visitor &visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const UnauthenticatedAttributes& unauthenticated_attributes) {
  if ((not unauthenticated_attributes.has_nested_signatures()) &&
    (not unauthenticated_attributes.has_counter_signatures()) &&
    (not unauthenticated_attributes.has_timestamping_signatures())) {
    os << "Do not have nested/counter/timestamping signature" << std::endl;
    return os;
  }

  if (unauthenticated_attributes.has_nested_signatures()) {
    os << "Nested signature" << std::endl;
    os << "================" << std::endl;
    for (const auto& nested_signature : unauthenticated_attributes.nested_signatures_) {
      os << *nested_signature << std::endl;
    }
  }
  if (unauthenticated_attributes.has_counter_signatures()) {
    os << "Counter signature" << std::endl;
    os << "=================" << std::endl;
    for (const auto& counter_signature : unauthenticated_attributes.counter_signatures_) {
      os << *counter_signature << std::endl;
    }
  }
  if (unauthenticated_attributes.has_timestamping_signatures()) {
    // TODO: to be implemented
    os << "Timestamping signature" << std::endl;
    os << "======================" << std::endl;
#if 0
    for (const auto& timestamping_signature : unauthenticated_attributes.timestamping_signatures_) {
      os << *timestamping_signature << std::endl;
    }
#else
    os << "currently not supported" << std::endl;
#endif
  }

  return os;
}

}
}
