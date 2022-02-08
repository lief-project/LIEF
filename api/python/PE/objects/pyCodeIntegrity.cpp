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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/CodeIntegrity.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (CodeIntegrity::*)(void) const;

template<class T>
using setter_t = void (CodeIntegrity::*)(T);


template<>
void create<CodeIntegrity>(py::module& m) {
  py::class_<CodeIntegrity, LIEF::Object>(m, "CodeIntegrity")
    .def(py::init<>())

    .def_property("flags",
        static_cast<getter_t<uint16_t>>(&CodeIntegrity::flags),
        static_cast<setter_t<uint16_t>>(&CodeIntegrity::flags),
        "Flags to indicate if CI information is available, etc.")

    .def_property("catalog",
        static_cast<getter_t<uint16_t>>(&CodeIntegrity::catalog),
        static_cast<setter_t<uint16_t>>(&CodeIntegrity::catalog),
        "``0xFFFF`` means not available")

    .def_property("catalog_offset",
        static_cast<getter_t<uint32_t>>(&CodeIntegrity::catalog_offset),
        static_cast<setter_t<uint32_t>>(&CodeIntegrity::catalog_offset),
        "")

    .def_property("reserved",
        static_cast<getter_t<uint32_t>>(&CodeIntegrity::reserved),
        static_cast<setter_t<uint32_t>>(&CodeIntegrity::reserved),
        "Additional bitmask to be defined later")


    .def("__eq__", &CodeIntegrity::operator==)
    .def("__ne__", &CodeIntegrity::operator!=)
    .def("__hash__",
        [] (const CodeIntegrity& code) {
          return Hash::hash(code);
        })


    .def("__str__", [] (const CodeIntegrity& code)
        {
          std::ostringstream stream;
          stream << code;
          std::string str = stream.str();
          return str;
        });
}

}
}
