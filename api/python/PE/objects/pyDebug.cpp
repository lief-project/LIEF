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
#include "LIEF/PE/Debug.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (Debug::*)(void) const;

template<class T>
using setter_t = void (Debug::*)(T);


template<>
void create<Debug>(py::module& m) {
  py::class_<Debug, LIEF::Object>(m, "Debug")
    .def(py::init<>())

    .def_property("characteristics",
        static_cast<getter_t<uint32_t>>(&Debug::characteristics),
        static_cast<setter_t<uint32_t>>(&Debug::characteristics),
        "Reserved should be 0")

    .def_property("timestamp",
        static_cast<getter_t<uint32_t>>(&Debug::timestamp),
        static_cast<setter_t<uint32_t>>(&Debug::timestamp),
        "The time and date that the debug data was created.")

    .def_property("major_version",
        static_cast<getter_t<uint16_t>>(&Debug::major_version),
        static_cast<setter_t<uint16_t>>(&Debug::major_version),
        "The major version number of the debug data format.")

    .def_property("minor_version",
        static_cast<getter_t<uint16_t>>(&Debug::minor_version),
        static_cast<setter_t<uint16_t>>(&Debug::minor_version),
        "The minor version number of the debug data format.")

    .def_property("type",
        static_cast<getter_t<DEBUG_TYPES>>(&Debug::type),
        static_cast<setter_t<DEBUG_TYPES>>(&Debug::type),
        "The format (" RST_CLASS_REF(lief.PE.DEBUG_TYPES) ") of the debugging information")

    .def_property("sizeof_data",
        static_cast<getter_t<uint32_t>>(&Debug::sizeof_data),
        static_cast<setter_t<uint32_t>>(&Debug::sizeof_data),
        "Size of the debug data")

    .def_property("addressof_rawdata",
        static_cast<getter_t<uint32_t>>(&Debug::addressof_rawdata),
        static_cast<setter_t<uint32_t>>(&Debug::addressof_rawdata),
        "Address of the debug data relative to the image base")

    .def_property("pointerto_rawdata",
        static_cast<getter_t<uint32_t>>(&Debug::pointerto_rawdata),
        static_cast<setter_t<uint32_t>>(&Debug::pointerto_rawdata),
        "File offset of the debug data")

    .def_property_readonly("has_code_view",
        &Debug::has_code_view,
        "Whether or not a code view is present")

    .def_property_readonly("code_view",
        static_cast<CodeView* (Debug::*)(void)>(&Debug::code_view),
        R"delim(
        Return an object which subclass :class:`~lief.PE.CodeView` representing the code view"
        The subclassed object can be one of:

            * :class:`~lief.PE.CodeViewPDB`

        If a code view is not present, it is set to None
        )delim",
        py::return_value_policy::reference)

    .def_property_readonly("has_pogo",
        &Debug::has_pogo,
        "Whether or not a pogo is present")

    .def_property_readonly("pogo",
        static_cast<Pogo* (Debug::*)(void)>(&Debug::pogo),
        R"delim(
        Return an object which subclasses :class:`~lief.PE.Pogo` representing the pogo entry.
        It returns None if not present.
        )delim",
        py::return_value_policy::reference)

    .def("__eq__", &Debug::operator==)
    .def("__ne__", &Debug::operator!=)
    .def("__hash__",
        [] (const Debug& debug) {
          return Hash::hash(debug);
        })

    .def("__str__", [] (const Debug& debug)
        {
          std::ostringstream stream;
          stream << debug;
          std::string str = stream.str();
          return str;
        });
}

}
}
