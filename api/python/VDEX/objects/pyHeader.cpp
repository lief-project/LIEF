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
#include "LIEF/VDEX/Header.hpp"
#include "LIEF/VDEX/hash.hpp"

#include "pyVDEX.hpp"

namespace LIEF {
namespace VDEX {

template<class T>
using getter_t = T (Header::*)(void) const;

template<class T>
using setter_t = void (Header::*)(T);

template<>
void create<Header>(py::module& m) {

  py::class_<Header, LIEF::Object>(m, "Header", "VDEX Header representation")

    .def_property_readonly("magic",
        static_cast<getter_t<Header::magic_t>>(&Header::magic),
        "Magic value used to identify VDEX")

    .def_property_readonly("version",
        static_cast<getter_t<vdex_version_t>>(&Header::version),
        "VDEX version number")

    .def_property_readonly("nb_dex_files",
        static_cast<getter_t<uint32_t>>(&Header::nb_dex_files),
        "Number of " RST_CLASS_REF(lief.DEX.File) " files registered")

    .def_property_readonly("dex_size",
        static_cast<getter_t<uint32_t>>(&Header::dex_size),
        "Size of **all** " RST_CLASS_REF(lief.DEX.File) "")

    .def_property_readonly("verifier_deps_size",
        static_cast<getter_t<uint32_t>>(&Header::verifier_deps_size),
        "Size of verifier deps section")

    .def_property_readonly("quickening_info_size",
        static_cast<getter_t<uint32_t>>(&Header::quickening_info_size),
        "Size of quickening info section")

    .def("__eq__", &Header::operator==)
    .def("__ne__", &Header::operator!=)
    .def("__hash__",
        [] (const Header& header) {
          return Hash::hash(header);
        })

    .def("__str__",
        [] (const Header& header)
        {
          std::ostringstream stream;
          stream << header;
          std::string str =  stream.str();
          return str;
        });
}

}
}

