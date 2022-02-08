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

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/DataDirectory.hpp"

#include "pyPE.hpp"

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (DataDirectory::*)(void) const;

template<class T>
using setter_t = void (DataDirectory::*)(T);


template<>
void create<DataDirectory>(py::module& m) {
  py::class_<DataDirectory, LIEF::Object>(m, "DataDirectory",
      R"delim(
      Class that represents a PE data directory entry
      )delim")
    .def(py::init<>())
    .def_property("rva",
        static_cast<getter_t<uint32_t>>(&DataDirectory::RVA),
        static_cast<setter_t<uint32_t>>(&DataDirectory::RVA),
        "**Relative** virtual address of the content associated with the current data directory")

    .def_property("size",
        static_cast<getter_t<uint32_t>>(&DataDirectory::size),
        static_cast<setter_t<uint32_t>>(&DataDirectory::size),
        "Size in bytes of the content associated with the current data directory")

    .def_property_readonly("section",
        static_cast<Section* (DataDirectory::*) (void)>(&DataDirectory::section),
        "" RST_CLASS_REF(lief.PE.Section) " associated with the current data directory or None if not linked",
        py::return_value_policy::reference)

    .def_property_readonly("type",
        &DataDirectory::type,
        "Type (" RST_CLASS_REF(lief.PE.DATA_DIRECTORY) ") of the current data directory",
        py::return_value_policy::reference_internal)

    .def_property_readonly("has_section",
        &DataDirectory::has_section,
        "``True`` if the current data directory is tied to a " RST_CLASS_REF(lief.PE.Section) "")

    .def("__eq__", &DataDirectory::operator==)
    .def("__ne__", &DataDirectory::operator!=)
    .def("__hash__",
        [] (const DataDirectory& data_directory) {
          return Hash::hash(data_directory);
        })

    .def("__str__", [] (const DataDirectory& datadir)
        {
          std::ostringstream stream;
          stream << datadir;
          std::string str =  stream.str();
          return str;
        });
}

}
}
