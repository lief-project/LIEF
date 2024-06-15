/* Copyright 2024 R. Thomas
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
#pragma once
#include <cstdint>

#include "LIEF/PE/signature/SignerInfo.hpp"
#include "LIEF/rust/PE/signature/attributes/Attribute.hpp"
#include "LIEF/rust/PE/signature/x509.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Span.hpp"

class PE_SignerInfo : private Mirror<LIEF::PE::SignerInfo> {
  public:
  using lief_t = LIEF::PE::SignerInfo;
  using Mirror::Mirror;

  class it_authenticated_attributes :
      public Iterator<PE_Attribute, LIEF::PE::SignerInfo::it_const_attributes_t>
  {
    public:
    it_authenticated_attributes(const PE_SignerInfo::lief_t& src)
      : Iterator(std::move(src.authenticated_attributes())) { } // NOLINT(performance-move-const-arg
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_unauthenticated_attributes :
      public Iterator<PE_Attribute, LIEF::PE::SignerInfo::it_const_attributes_t>
  {
    public:
    it_unauthenticated_attributes(const PE_SignerInfo::lief_t& src)
      : Iterator(std::move(src.unauthenticated_attributes())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  uint32_t version() const { return get().version(); }
  std::string issuer() const { return get().issuer(); }
  uint32_t digest_algorithm() const { return to_int(get().digest_algorithm()); }
  uint32_t encryption_algorithm() const { return to_int(get().encryption_algorithm()); }
  Span serial_number() const { return make_span(get().serial_number()); }

  std::vector<uint8_t> encrypted_digest() const {
    return get().encrypted_digest();
  }

  auto cert() const {
    return details::try_unique<PE_x509>(get().cert()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto authenticated_attributes() const {
    return std::make_unique<it_authenticated_attributes>(get());
  }

  auto unauthenticated_attributes() const {
    return std::make_unique<it_unauthenticated_attributes>(get());
  }

  auto raw_auth_data() const {
    return make_span(get().raw_auth_data());
  }
};
