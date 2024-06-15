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

#include "LIEF/BinaryStream/SpanStream.hpp"
#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/SignatureParser.hpp"
#include "LIEF/rust/PE/signature/ContentInfo.hpp"
#include "LIEF/rust/PE/signature/x509.hpp"
#include "LIEF/rust/PE/signature/SignerInfo.hpp"
#include "LIEF/rust/Span.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_Signature : private Mirror<LIEF::PE::Signature> {
  friend class PE_Binary;
  public:
  using lief_t = LIEF::PE::Signature;
  using Mirror::Mirror;

  class it_certificates :
      public Iterator<PE_x509, LIEF::PE::Signature::it_const_crt>
  {
    public:
    it_certificates(const PE_Signature::lief_t& src)
      : Iterator(std::move(src.certificates())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_signers :
      public Iterator<PE_SignerInfo, LIEF::PE::Signature::it_const_signers_t>
  {
    public:
    it_signers(const PE_Signature::lief_t& src)
      : Iterator(std::move(src.signers())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  static auto parse(std::string path) { // NOLINT(performance-unnecessary-value-param)
    auto res = LIEF::PE::SignatureParser::parse(path);
    std::unique_ptr<LIEF::PE::Signature> sig;
    if (res) {
      sig = std::make_unique<LIEF::PE::Signature>(std::move(*res));
    }
    return sig ? std::make_unique<PE_Signature>(std::move(sig)) : nullptr;
  }

  static auto from_raw(uint8_t* buffer, size_t size) {
    LIEF::SpanStream stream(buffer, size);
    auto res = LIEF::PE::SignatureParser::parse(stream);
    std::unique_ptr<LIEF::PE::Signature> sig;
    if (res) {
      sig = std::make_unique<LIEF::PE::Signature>(std::move(*res));
    }
    return sig ? std::make_unique<PE_Signature>(std::move(sig)) : nullptr;
  }


  auto version() const { return get().version(); }
  auto digest_algorithm() const { return to_int(get().digest_algorithm()); }
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

  auto find_crt_by_serial(const uint8_t* serial, size_t size) const {
    return details::try_unique<PE_x509>(get().find_crt(std::vector<uint8_t>{serial, serial + size})); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto find_crt_by_subject(std::string subject) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<PE_x509>(get().find_crt_subject(subject)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto find_crt_by_subject_and_serial(std::string subject, // NOLINT(performance-unnecessary-value-param)
                                      const uint8_t* serial, size_t size) const {
    std::vector<uint8_t> serial_vec{serial, serial + size};
    return details::try_unique<PE_x509>(get().find_crt_subject(subject, serial_vec)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto find_crt_by_issuer(std::string issuer) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<PE_x509>(get().find_crt_issuer(issuer)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto find_crt_by_issuer_and_serial(std::string issuer, // NOLINT(performance-unnecessary-value-param)
                                     const uint8_t* serial, size_t size) const {
    std::vector<uint8_t> serial_vec{serial, serial + size};
    return details::try_unique<PE_x509>(get().find_crt_issuer(issuer, serial_vec)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto check(uint32_t flags) const {
    return to_int(get().check(LIEF::PE::Signature::VERIFICATION_CHECKS(flags)));
  }

};
