/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

#include "LIEF/visitors/Hash.hpp"
#include "LIEF/PE/Debug.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (Debug::*)(void) const;

template<class T>
using setter_t = void (Debug::*)(T);

void init_PE_Debug_class(py::module& m) {
  py::class_<Debug>(m, "Debug")
    .def(py::init<>())

    .def_property("characteristics",
        static_cast<getter_t<uint32_t>>(&Debug::characteristics),
        static_cast<setter_t<uint32_t>>(&Debug::characteristics))

    .def_property("timestamp",
        static_cast<getter_t<uint32_t>>(&Debug::timestamp),
        static_cast<setter_t<uint32_t>>(&Debug::timestamp))

    .def_property("major_version",
        static_cast<getter_t<uint16_t>>(&Debug::major_version),
        static_cast<setter_t<uint16_t>>(&Debug::major_version))

    .def_property("minor_version",
        static_cast<getter_t<uint16_t>>(&Debug::minor_version),
        static_cast<setter_t<uint16_t>>(&Debug::minor_version))

    .def_property("type",
        static_cast<getter_t<DEBUG_TYPES>>(&Debug::type),
        static_cast<setter_t<DEBUG_TYPES>>(&Debug::type))

    .def_property("sizeof_data",
        static_cast<getter_t<uint32_t>>(&Debug::sizeof_data),
        static_cast<setter_t<uint32_t>>(&Debug::sizeof_data))

    .def_property("addressof_rawdata",
        static_cast<getter_t<uint32_t>>(&Debug::addressof_rawdata),
        static_cast<setter_t<uint32_t>>(&Debug::addressof_rawdata))

    .def_property("pointerto_rawdata",
        static_cast<getter_t<uint32_t>>(&Debug::pointerto_rawdata),
        static_cast<setter_t<uint32_t>>(&Debug::pointerto_rawdata))

    .def("__eq__", &Debug::operator==)
    .def("__ne__", &Debug::operator!=)
    .def("__hash__",
        [] (const Debug& debug) {
          return LIEF::Hash::hash(debug);
        })

    .def("__str__", [] (const Debug& debug)
        {
          std::ostringstream stream;
          stream << debug;
          std::string str = stream.str();
          return str;
        });


}
