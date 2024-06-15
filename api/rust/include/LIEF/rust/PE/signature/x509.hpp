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

#include "LIEF/PE/signature/x509.hpp"
#include "LIEF/rust/PE/signature/RsaInfo.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_x509 : private Mirror<LIEF::PE::x509> {
  public:
  using lief_t = LIEF::PE::x509;
  using Mirror::Mirror;

  uint32_t version() const { return get().version(); }
  std::vector<uint8_t> serial_number() const { return get().serial_number(); }

  std::string signature_algorithm() const { return get().signature_algorithm(); }
  std::vector<uint64_t> valid_from() const {
    return details::make_vector(get().valid_from());
  }

  std::vector<uint64_t> valid_to() const {
    return details::make_vector(get().valid_to());
  }

  std::string issuer() const { return get().issuer(); }
  std::string subject() const { return get().subject(); }
  std::vector<uint8_t> raw() const { return get().raw(); }

  uint32_t key_type() const { return to_int(get().key_type()); }
  bool is_ca() const { return get().is_ca(); }
  std::vector<uint8_t> signature() const { return get().signature(); }

  auto rsa_info() const {
    return std::make_unique<PE_RsaInfo>(get().rsa_info());
  }

  auto check_signature(const uint8_t* hash, size_t hsize,
                       const uint8_t* signature, size_t sigsiz,
                       uint32_t algo) const
  {
    return get().check_signature({hash, hash + hsize}, {signature, signature + sigsiz},
                           LIEF::PE::ALGORITHMS(algo));
  }

  auto verify(const PE_x509& ca) const {
    return to_int(get().verify(ca.get()));
  }
};
