/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include "pyIterator.hpp"

#include "LIEF/PE/ResourceDirectory.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<ResourceDirectory>(nb::module_& m) {
  nb::class_<ResourceDirectory, ResourceNode>(m, "ResourceDirectory")
    .def(nb::init<>(),
        "Default constructor"_doc)

    .def_prop_rw("characteristics",
        nb::overload_cast<>(&ResourceDirectory::characteristics, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceDirectory::characteristics),
        "Resource characteristics. This field is reserved for future use. "
        "It is currently set to zero."_doc)

    .def_prop_rw("time_date_stamp",
        nb::overload_cast<>(&ResourceDirectory::time_date_stamp, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceDirectory::time_date_stamp),
        "The time that the resource data was created by the "
        "resource compiler."_doc)

    .def_prop_rw("major_version",
        nb::overload_cast<>(&ResourceDirectory::major_version, nb::const_),
        nb::overload_cast<uint16_t>(&ResourceDirectory::major_version),
        "The major version number, set by the user."_doc)

    .def_prop_rw("minor_version",
        nb::overload_cast<>(&ResourceDirectory::minor_version, nb::const_),
        nb::overload_cast<uint16_t>(&ResourceDirectory::minor_version),
        "The minor version number, set by the user."_doc)

    .def_prop_rw("numberof_name_entries",
        nb::overload_cast<>(&ResourceDirectory::numberof_name_entries, nb::const_),
        nb::overload_cast<uint16_t>(&ResourceDirectory::numberof_name_entries),
        "The number of directory entries immediately "
        "following the table that use strings to identify Type, "
        "Name, or Language entries (depending on the level "
        "of the table"_doc)

    .def_prop_rw("numberof_id_entries",
        nb::overload_cast<>(&ResourceDirectory::numberof_id_entries, nb::const_),
        nb::overload_cast<uint16_t>(&ResourceDirectory::numberof_id_entries),
        "The number of directory entries immediately "
        "following the Name entries that use numeric IDs for "
        "Type, Name, or Language entries."_doc)

    LIEF_DEFAULT_STR(ResourceDirectory);
}

}
