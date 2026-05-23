/* Copyright 2024 - 2026 R. Thomas
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

#include "LIEF/PE/signature/x509.hpp"
#include "LIEF/rust/PE/signature/RsaInfo.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_x509 : private Mirror<LIEF::PE::x509> {
  public:
  using lief_t = LIEF::PE::x509;
  using Mirror::Mirror;

  uint32_t version() const {
    return get().version();
  }
  auto serial_number() const {
    return make_unique_vector<uint8_t>(get().serial_number());
  }

  auto signature_algorithm() const {
    return to_unique_string(get().signature_algorithm());
  }
  auto valid_from() const {
    return make_unique_vector<uint64_t>(details::make_vector(get().valid_from()));
  }

  auto valid_to() const {
    return make_unique_vector<uint64_t>(details::make_vector(get().valid_to()));
  }

  auto issuer() const {
    return to_unique_string(get().issuer());
  }
  auto subject() const {
    return to_unique_string(get().subject());
  }
  auto raw() const {
    return make_unique_vector<uint8_t>(get().raw());
  }

  auto key_type() const {
    return as_u32(get().key_type());
  }
  auto is_ca() const {
    return get().is_ca();
  }
  auto signature() const {
    return make_unique_vector<uint8_t>(get().signature());
  }

  auto rsa_info() const {
    return std::make_unique<PE_RsaInfo>(get().rsa_info());
  }

  auto check_signature(const uint8_t* hash, size_t hsize, const uint8_t* signature,
                       size_t sigsiz, uint32_t algo) const {
    return as_u32(get().check_signature({hash, hash + hsize},
                                        {signature, signature + sigsiz},
                                        LIEF::PE::ALGORITHMS(algo)));
  }

  auto verify(const PE_x509& ca) const {
    return as_u32(get().verify(ca.get()));
  }

  auto key_usage() const {
    auto result = make_unique_vector<uint32_t>();
    for (LIEF::PE::x509::KEY_USAGE ku : get().key_usage()) {
      result->push_back(to_int(ku));
    }
    return result;
  }
  auto ext_key_usage() const {
    auto v = get().ext_key_usage();
    return make_unique_vector<std::string>(v.begin(), v.end());
  }
  auto certificate_policies() const {
    auto v = get().certificate_policies();
    return make_unique_vector<std::string>(v.begin(), v.end());
  }
};
