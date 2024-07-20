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
#include "LIEF/PE/signature/attributes/MsCounterSign.hpp"
#include "LIEF/rust/PE/signature/x509.hpp"
#include "LIEF/rust/PE/signature/SignerInfo.hpp"
#include "LIEF/rust/PE/signature/ContentInfo.hpp"
#include "LIEF/rust/PE/signature/attributes/Attribute.hpp"

class PE_MsCounterSign : public PE_Attribute {
  public:
  using lief_t = LIEF::PE::MsCounterSign;
  PE_MsCounterSign(const lief_t& base) : PE_Attribute(base) {}

  class it_certificates :
      public Iterator<PE_x509, lief_t::it_const_certificates>
  {
    public:
    it_certificates(const PE_MsCounterSign::lief_t& src)
      : Iterator(std::move(src.certificates())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_signers :
      public Iterator<PE_SignerInfo, lief_t::it_const_signers>
  {
    public:
    it_signers(const PE_MsCounterSign::lief_t& src)
      : Iterator(std::move(src.signers())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  static bool classof(const PE_Attribute& attr) {
    return lief_t::classof(&attr.get());
  }

  auto version() const { return impl().version(); }
  auto digest_algorithm() const { return to_int(impl().digest_algorithm()); }

  auto content_info() const {
    return std::make_unique<PE_ContentInfo>(impl().content_info());
  }

  auto certificates() const {
    return std::make_unique<it_certificates>(impl());
  }

  auto signers() const {
    return std::make_unique<it_signers>(impl());
  }


  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
