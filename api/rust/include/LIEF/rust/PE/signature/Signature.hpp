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

#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/SignatureParser.hpp"
#include "LIEF/rust/PE/signature/ContentInfo.hpp"
#include "LIEF/rust/PE/signature/x509.hpp"
#include "LIEF/rust/PE/signature/SignerInfo.hpp"
#include "LIEF/rust/Span.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_Signature : private Mirror<LIEF::PE::Signature> {
  public:
  using lief_t = LIEF::PE::Signature;
  using Mirror::Mirror;

  class it_certificates :
      public Iterator<PE_x509, LIEF::PE::Signature::it_const_crt>
  {
    public:
    it_certificates(const PE_Signature::lief_t& src)
      : Iterator(std::move(src.certificates())) { }
    auto next() { return Iterator::next(); }
  };

  class it_signers :
      public Iterator<PE_SignerInfo, LIEF::PE::Signature::it_const_signers_t>
  {
    public:
    it_signers(const PE_Signature::lief_t& src)
      : Iterator(std::move(src.signers())) { }
    auto next() { return Iterator::next(); }
  };

  static auto parse(std::string path) {
    auto res = LIEF::PE::SignatureParser::parse(path);
    std::unique_ptr<LIEF::PE::Signature> sig;
    if (res) {
      sig = std::make_unique<LIEF::PE::Signature>(std::move(*res));
    }
    return sig ? std::make_unique<PE_Signature>(std::move(sig)) : nullptr;
  }


  uint32_t version() const { return get().version(); }
  uint32_t digest_algorithm() const { return to_int(get().digest_algorithm()); }
  auto raw_der() const { return make_span(get().raw_der()); }

  auto content_info() const {
    return std::make_unique<PE_ContentInfo>(get().content_info());
  }

  auto certificates() const {
    return std::make_unique<it_certificates>(get());
  }

  auto signers() const {
    return std::make_unique<it_signers>(get());
  }
};
