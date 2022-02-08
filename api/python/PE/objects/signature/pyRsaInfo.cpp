/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include <string>
#include <sstream>

#include "LIEF/PE/signature/RsaInfo.hpp"

#include "pyPE.hpp"

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (RsaInfo::*)(void) const;

template<class T>
using setter_t = void (RsaInfo::*)(T);


template<>
void create<RsaInfo>(py::module& m) {

  py::class_<RsaInfo>(m, "RsaInfo", "Object representing a RSA key")
    .def_property_readonly("has_public_key",
        &RsaInfo::has_public_key,
        "True if it embeds a public key")

    .def_property_readonly("has_private_key",
        &RsaInfo::has_private_key,
        "True if it embeds a private key")

    .def_property_readonly("N",
        [] (const RsaInfo& info) {
          const std::vector<uint8_t>& data = info.N();
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        },
        "RSA public modulus (in bytes)")

    .def_property_readonly("E",
        [] (const RsaInfo& info) {
          const std::vector<uint8_t>& data = info.E();
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        }, "RSA public exponent (in bytes)")

    .def_property_readonly("D",
        [] (const RsaInfo& info) {
          const std::vector<uint8_t>& data = info.D();
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        }, "RSA private exponent (in bytes)")

    .def_property_readonly("P",
        [] (const RsaInfo& info) {
          const std::vector<uint8_t>& data = info.P();
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        }, "First prime factor (in bytes)")

    .def_property_readonly("Q",
        [] (const RsaInfo& info) {
          const std::vector<uint8_t>& data = info.Q();
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        }, "Second prime factor (in bytes)")

    .def_property_readonly("key_size",
        &RsaInfo::key_size, "Size of the public modulus in bits")

    .def_property_readonly("__len__",
        &RsaInfo::key_size)

    .def("__str__",
        [] (const RsaInfo& info)
        {
          std::ostringstream stream;
          stream << info;
          return safe_string_converter(stream.str());
        });
}

}
}

