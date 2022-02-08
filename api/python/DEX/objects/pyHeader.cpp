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
#include "LIEF/DEX/Header.hpp"
#include "LIEF/DEX/hash.hpp"

#include "pyDEX.hpp"

namespace LIEF {
namespace DEX {

template<class T>
using getter_t = T (Header::*)(void) const;

template<class T>
using setter_t = void (Header::*)(T);

template<>
void create<Header>(py::module& m) {

  py::class_<Header, LIEF::Object>(m, "Header", "DEX Header")

    .def_property_readonly("magic",
        static_cast<getter_t<Header::magic_t>>(&Header::magic),
        "Magic value")

    .def_property_readonly("checksum",
        static_cast<getter_t<uint32_t>>(&Header::checksum),
        "Checksum value of the rest of the file (without " RST_ATTR_REF(lief.DEX.Header.magic) ")")

    .def_property_readonly("signature",
        static_cast<getter_t<Header::signature_t>>(&Header::signature),
        "SHA-1 signature of the rest of the file (without " RST_ATTR_REF(lief.DEX.Header.magic) " and " RST_ATTR_REF(lief.DEX.Header.checksum) ")")

    .def_property_readonly("file_size",
        static_cast<getter_t<uint32_t>>(&Header::file_size),
        "Size of the current DEX file")

    .def_property_readonly("header_size",
        static_cast<getter_t<uint32_t>>(&Header::header_size),
        "Size of this header. Should be ``0x70``")

    .def_property_readonly("endian_tag",
        static_cast<getter_t<uint32_t>>(&Header::endian_tag),
        "Endianness tag. Should be ``ENDIAN_CONSTANT``")

    .def_property_readonly("map_offset",
        static_cast<getter_t<uint32_t>>(&Header::map),
        "Offset from the start of the file to the map item")

    .def_property_readonly("strings",
        static_cast<getter_t<Header::location_t>>(&Header::strings),
        "String identifiers")

    .def_property_readonly("link",
        static_cast<getter_t<Header::location_t>>(&Header::link),
        "Link (raw data)")

    .def_property_readonly("types",
        static_cast<getter_t<Header::location_t>>(&Header::types),
        "Type identifiers")

    .def_property_readonly("prototypes",
        static_cast<getter_t<Header::location_t>>(&Header::prototypes),
        "Prototypes identifiers")

    .def_property_readonly("fields",
        static_cast<getter_t<Header::location_t>>(&Header::fields),
        "Fields identifiers")

    .def_property_readonly("methods",
        static_cast<getter_t<Header::location_t>>(&Header::methods),
        "Methods identifiers")

    .def_property_readonly("classes",
        static_cast<getter_t<Header::location_t>>(&Header::classes),
        "Classess identifiers")

    .def_property_readonly("data",
        static_cast<getter_t<Header::location_t>>(&Header::data),
        "Raw data. Should be align on 32-bits")

    .def_property_readonly("nb_classes",
        static_cast<getter_t<uint32_t>>(&Header::nb_classes),
        "Number of classes in the current DEX")

    .def_property_readonly("nb_methods",
        static_cast<getter_t<uint32_t>>(&Header::nb_methods),
        "Number of methods in the current DEX")

    .def("__eq__", &Header::operator==)
    .def("__ne__", &Header::operator!=)
    .def("__hash__",
        [] (const Header& header) {
          return Hash::hash(header);
        })

    .def("__str__",
        [] (const Header& header) {
          std::ostringstream stream;
          stream << header;
          return stream.str();
        });

}

}
}


