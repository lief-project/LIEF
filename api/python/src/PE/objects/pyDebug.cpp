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

#include "LIEF/PE/Debug.hpp"
#include "LIEF/PE/Pogo.hpp"
#include "LIEF/PE/CodeView.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<Debug>(nb::module_& m) {
  nb::class_<Debug, LIEF::Object>(m, "Debug")
    .def(nb::init<>())

    .def_prop_rw("characteristics",
        nb::overload_cast<>(&Debug::characteristics, nb::const_),
        nb::overload_cast<uint32_t>(&Debug::characteristics),
        "Reserved should be 0"_doc)

    .def_prop_rw("timestamp",
        nb::overload_cast<>(&Debug::timestamp, nb::const_),
        nb::overload_cast<uint32_t>(&Debug::timestamp),
        "The time and date that the debug data was created."_doc)

    .def_prop_rw("major_version",
        nb::overload_cast<>(&Debug::major_version, nb::const_),
        nb::overload_cast<uint16_t>(&Debug::major_version),
        "The major version number of the debug data format."_doc)

    .def_prop_rw("minor_version",
        nb::overload_cast<>(&Debug::minor_version, nb::const_),
        nb::overload_cast<uint16_t>(&Debug::minor_version),
        "The minor version number of the debug data format."_doc)

    .def_prop_rw("type",
        nb::overload_cast<>(&Debug::type, nb::const_),
        nb::overload_cast<DEBUG_TYPES>(&Debug::type),
        "The format (" RST_CLASS_REF(lief.PE.DEBUG_TYPES) ") of the debugging information"_doc)

    .def_prop_rw("sizeof_data",
        nb::overload_cast<>(&Debug::sizeof_data, nb::const_),
        nb::overload_cast<uint32_t>(&Debug::sizeof_data),
        "Size of the debug data"_doc)

    .def_prop_rw("addressof_rawdata",
        nb::overload_cast<>(&Debug::addressof_rawdata, nb::const_),
        nb::overload_cast<uint32_t>(&Debug::addressof_rawdata),
        "Address of the debug data relative to the image base"_doc)

    .def_prop_rw("pointerto_rawdata",
        nb::overload_cast<>(&Debug::pointerto_rawdata, nb::const_),
        nb::overload_cast<uint32_t>(&Debug::pointerto_rawdata),
        "File offset of the debug data"_doc)

    .def_prop_ro("has_code_view",
        &Debug::has_code_view,
        "Whether or not a code view is present"_doc)

    .def_prop_ro("code_view",
        nb::overload_cast<>(&Debug::code_view),
        R"delim(
        Return an object which subclass :class:`~lief.PE.CodeView` representing the code view"
        The subclassed object can be one of:

            * :class:`~lief.PE.CodeViewPDB`

        If a code view is not present, it is set to None
        )delim"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_pogo",
        &Debug::has_pogo,
        "Whether or not a pogo is present"_doc)

    .def_prop_ro("pogo",
        nb::overload_cast<>(&Debug::pogo),
        R"delim(
        Return an object which subclasses :class:`~lief.PE.Pogo` representing the pogo entry.
        It returns None if not present.
        )delim"_doc,
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(LIEF::PE::Debug);
}

}

