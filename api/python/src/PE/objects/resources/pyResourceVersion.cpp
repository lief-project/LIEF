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

#include "LIEF/PE/resources/ResourceVersion.hpp"
#include "LIEF/PE/resources/ResourceVarFileInfo.hpp"
#include "LIEF/PE/resources/ResourceStringFileInfo.hpp"
#include "LIEF/PE/resources/ResourceFixedFileInfo.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/extra/stl/u16string.h>

namespace LIEF::PE::py {

template<>
void create<ResourceVersion>(nb::module_& m) {
  nb::class_<ResourceVersion, LIEF::Object>(m, "ResourceVersion",
      R"delim(
      Class that represents the data associated with the ``RT_VERSION`` entry

      See: `VS_VERSIONINFO <https://docs.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo>`_
      )delim"_doc)

    .def_prop_rw("type",
        nb::overload_cast<>(&ResourceVersion::type, nb::const_),
        nb::overload_cast<uint16_t>(&ResourceVersion::type),
        R"delim(
        The type of data in the version resource
          * ``1`` if it contains text data
          * ``0`` if it contains binary data
        )delim"_doc)

    .def_prop_rw("key",
        nb::overload_cast<>(&ResourceVersion::key, nb::const_),
        nb::overload_cast<const std::string&>(&ResourceVersion::key),
        "Signature of the structure. Must be ``VS_VERSION_INFO``"_doc)

    .def_prop_rw("fixed_file_info",
        nb::overload_cast<>(&ResourceVersion::fixed_file_info, nb::const_),
        nb::overload_cast<const ResourceFixedFileInfo&>(&ResourceVersion::fixed_file_info),
        R"delim(
        :class:`~lief.PE.ResourceFixedFileInfo` associated with the version (if any).
        This object describes various information about the application's version.

        If not present, this property is set to None
        )delim"_doc)

    .def_prop_rw("string_file_info",
        nb::overload_cast<>(&ResourceVersion::string_file_info, nb::const_),
        nb::overload_cast<const ResourceStringFileInfo&>(&ResourceVersion::string_file_info),
        R"delim(
        :class:`~lief.PE.ResourceStringFileInfo` associated with the version (if any)
        This object describes various information about the application's version.
        The underlying structure is basically a dictionary (key/value)

        If the current :class:`~lief.PE.ResourceVersion` does not use :class:`~lief.PE.ResourceStringFileInfo`,
        it returns None.
        )delim"_doc)

    .def_prop_rw("var_file_info",
        nb::overload_cast<>(&ResourceVersion::var_file_info, nb::const_),
        nb::overload_cast<const ResourceVarFileInfo&>(&ResourceVersion::var_file_info),
        R"delim(
        :class:`~lief.PE.ResourceVarFileInfo` associated with the version (if any)
        This object describes information about languages supported by the application.

        If the current :class:`~lief.PE.ResourceVersion` does not use :class:`~lief.PE.ResourceVarFileInfo`,
        it returns None.
        )delim"_doc)

    .def_prop_ro("has_fixed_file_info",
        &ResourceVersion::has_fixed_file_info,
        "``True`` if the version contains a " RST_CLASS_REF(lief.PE.ResourceFixedFileInfo) ""_doc)

    .def_prop_ro("has_string_file_info",
        &ResourceVersion::has_string_file_info,
        "``True`` if the version contains a " RST_CLASS_REF(lief.PE.ResourceStringFileInfo) ""_doc)

    .def_prop_ro("has_var_file_info",
        &ResourceVersion::has_var_file_info,
        "``True`` if the version contains a " RST_CLASS_REF(lief.PE.ResourceVarFileInfo) ""_doc)

    .def("remove_fixed_file_info",
        &ResourceVersion::remove_fixed_file_info,
        "Remove the " RST_CLASS_REF(lief.PE.ResourceFixedFileInfo) " from the version"_doc)

    .def("remove_string_file_info",
        &ResourceVersion::remove_string_file_info,
        "Remove the " RST_CLASS_REF(lief.PE.ResourceStringFileInfo) " from the version"_doc)

    .def("remove_var_file_info",
        &ResourceVersion::remove_var_file_info,
        "Remove the " RST_CLASS_REF(lief.PE.ResourceVarFileInfo) " from the version"_doc)

    LIEF_DEFAULT_STR(ResourceVersion);
}

}

