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
#include "pyIterators.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (ResourceDirectory::*)(void) const;

template<class T>
using setter_t = void (ResourceDirectory::*)(T);


template<>
void create<ResourceDirectory>(py::module& m) {
  py::class_<ResourceDirectory, ResourceNode>(m, "ResourceDirectory")
    .def(py::init<>(),
        "Default constructor")

    .def_property("characteristics",
        static_cast<getter_t<uint32_t>>(&ResourceDirectory::characteristics),
        static_cast<setter_t<uint32_t>>(&ResourceDirectory::characteristics),
        "Resource characteristics. This field is reserved for future use. "
        "It is currently set to zero.")

    .def_property("time_date_stamp",
        static_cast<getter_t<uint32_t>>(&ResourceDirectory::time_date_stamp),
        static_cast<setter_t<uint32_t>>(&ResourceDirectory::time_date_stamp),
        "The time that the resource data was created by the "
        "resource compiler.")

    .def_property("major_version",
        static_cast<getter_t<uint16_t>>(&ResourceDirectory::major_version),
        static_cast<setter_t<uint16_t>>(&ResourceDirectory::major_version),
        "The major version number, set by the user.")

    .def_property("minor_version",
        static_cast<getter_t<uint16_t>>(&ResourceDirectory::minor_version),
        static_cast<setter_t<uint16_t>>(&ResourceDirectory::minor_version),
        "The minor version number, set by the user.")

    .def_property("numberof_name_entries",
        static_cast<getter_t<uint16_t>>(&ResourceDirectory::numberof_name_entries),
        static_cast<setter_t<uint16_t>>(&ResourceDirectory::numberof_name_entries),
        "The number of directory entries immediately "
        "following the table that use strings to identify Type, "
        "Name, or Language entries (depending on the level "
        "of the table")

    .def_property("numberof_id_entries",
        static_cast<getter_t<uint16_t>>(&ResourceDirectory::numberof_id_entries),
        static_cast<setter_t<uint16_t>>(&ResourceDirectory::numberof_id_entries),
        "The number of directory entries immediately "
        "following the Name entries that use numeric IDs for "
        "Type, Name, or Language entries.")


    .def("__eq__", &ResourceDirectory::operator==)
    .def("__ne__", &ResourceDirectory::operator!=)

    .def("__hash__",
        [] (const ResourceDirectory& node) {
          return Hash::hash(node);
        })

    .def("__str__",
        [] (const ResourceDirectory& directory) {
          std::ostringstream stream;
          stream << directory;
          std::string str = stream.str();
          return str;
        });
}

}
}
