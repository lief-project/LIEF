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

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/resources/ResourceVersion.hpp"

#include <string>
#include <sstream>


template<class T>
using getter_t = T (ResourceVersion::*)(void) const;

template<class T>
using setter_t = void (ResourceVersion::*)(T);

void init_PE_ResourceVersion_class(py::module& m) {
  py::class_<ResourceVersion, LIEF::Object>(m, "ResourceVersion",
      "Modelization of the data associated with the ``RT_VERSION`` entry\n"
      "See: `VS_VERSIONINFO <https://msdn.microsoft.com/en-us/library/windows/desktop/ms647001(v=vs.85).aspx>`_")

    .def_property("type",
        static_cast<getter_t<uint16_t>>(&ResourceVersion::type),
        static_cast<setter_t<uint16_t>>(&ResourceVersion::type),
        "The type of data in the version resource\n\n"
        "* ``1`` if it contains text data\n"
        "* ``0`` if it contains binary data\n")

    .def_property("key",
        static_cast<getter_t<const std::u16string&>>(&ResourceVersion::key),
        static_cast<setter_t<const std::string&>>(&ResourceVersion::key),
        "Signature of the structure. Must be ``VS_VERSION_INFO``")

    .def_property("fixed_file_info",
        static_cast<getter_t<const ResourceFixedFileInfo&>>(&ResourceVersion::fixed_file_info),
        static_cast<setter_t<const ResourceFixedFileInfo&>>(&ResourceVersion::fixed_file_info),
        "" RST_CLASS_REF(lief.PE.ResourceFixedFileInfo) " associated with the version (if any).\n\n"
        "This object describes various information about the application's version")

    .def_property("string_file_info",
        static_cast<getter_t<const ResourceStringFileInfo&>>(&ResourceVersion::string_file_info),
        static_cast<setter_t<const ResourceStringFileInfo&>>(&ResourceVersion::string_file_info),
        "" RST_CLASS_REF(lief.PE.ResourceStringFileInfo) " associated with the version (if any)\n\n"
        "This object describes various information about the application's version.\n"
        "The underlying structure is basically a dictionary (key/value)")

    .def_property("var_file_info",
        static_cast<getter_t<const ResourceVarFileInfo&>>(&ResourceVersion::var_file_info),
        static_cast<setter_t<const ResourceVarFileInfo&>>(&ResourceVersion::var_file_info),
        "" RST_CLASS_REF(lief.PE.ResourceVarFileInfo) " associated with the version (if any)\n\n"
        "This object describes information about languages supported by the application")

    .def_property_readonly("has_fixed_file_info",
        &ResourceVersion::has_fixed_file_info,
        "``True`` if the version contains a " RST_CLASS_REF(lief.PE.ResourceFixedFileInfo) "")

    .def_property_readonly("has_string_file_info",
        &ResourceVersion::has_string_file_info,
        "``True`` if the version contains a " RST_CLASS_REF(lief.PE.ResourceStringFileInfo) "")

    .def_property_readonly("has_var_file_info",
        &ResourceVersion::has_var_file_info,
        "``True`` if the version contains a " RST_CLASS_REF(lief.PE.ResourceVarFileInfo) "")

    .def("remove_fixed_file_info",
        &ResourceVersion::remove_fixed_file_info,
        "Remove the " RST_CLASS_REF(lief.PE.ResourceFixedFileInfo) " from the version")

    .def("remove_string_file_info",
        &ResourceVersion::remove_string_file_info,
        "Remove the " RST_CLASS_REF(lief.PE.ResourceStringFileInfo) " from the version")

    .def("remove_var_file_info",
        &ResourceVersion::remove_var_file_info,
        "Remove the " RST_CLASS_REF(lief.PE.ResourceVarFileInfo) " from the version")

    .def("__eq__", &ResourceVersion::operator==)
    .def("__ne__", &ResourceVersion::operator!=)
    .def("__hash__",
        [] (const ResourceVersion& version) {
          return Hash::hash(version);
        })

    .def("__str__",
        [] (const ResourceVersion& version) {
          std::ostringstream stream;
          stream << version;
          std::string str = stream.str();
          return str;
        });
}

