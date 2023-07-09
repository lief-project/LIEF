/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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
#include "PE/pyPE.hpp"

#include "LIEF/PE/signature/RsaInfo.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<RsaInfo>(nb::module_& m) {

  nb::class_<RsaInfo>(m, "RsaInfo", "Object representing a RSA key")
    .def_prop_ro("has_public_key",
        &RsaInfo::has_public_key,
        "True if it embeds a public key"_doc)

    .def_prop_ro("has_private_key",
        &RsaInfo::has_private_key,
        "True if it embeds a private key"_doc)

    .def_prop_ro("N",
        [] (const RsaInfo& info) {
          const std::vector<uint8_t>& data = info.N();
          return nb::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        },
        "RSA public modulus (in bytes)"_doc)

    .def_prop_ro("E",
        [] (const RsaInfo& info) {
          const std::vector<uint8_t>& data = info.E();
          return nb::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        }, "RSA public exponent (in bytes)"_doc)

    .def_prop_ro("D",
        [] (const RsaInfo& info) {
          const std::vector<uint8_t>& data = info.D();
          return nb::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        }, "RSA private exponent (in bytes)"_doc)

    .def_prop_ro("P",
        [] (const RsaInfo& info) {
          const std::vector<uint8_t>& data = info.P();
          return nb::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        }, "First prime factor (in bytes)"_doc)

    .def_prop_ro("Q",
        [] (const RsaInfo& info) {
          const std::vector<uint8_t>& data = info.Q();
          return nb::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        }, "Second prime factor (in bytes)")

    .def_prop_ro("key_size",
        &RsaInfo::key_size, "Size of the public modulus in bits"_doc)

    .def_prop_ro("__len__",
        &RsaInfo::key_size)

    LIEF_DEFAULT_STR(RsaInfo);
}

}

