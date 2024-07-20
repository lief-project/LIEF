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

#include "LIEF/PE/resources/ResourceVarFileInfo.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/extra/stl/u16string.h>

namespace LIEF::PE::py {

template<>
void create<ResourceVarFileInfo>(nb::module_& m) {
  nb::class_<ResourceVarFileInfo, LIEF::Object>(m, "ResourceVarFileInfo",
      "This object describes information about languages supported by the application"_doc)

    .def_prop_rw("type",
        nb::overload_cast<>(&ResourceVarFileInfo::type, nb::const_),
        nb::overload_cast<uint16_t>(&ResourceVarFileInfo::type),
        R"delim(
        The type of data in the version resource

          * ``1`` if it contains text data
          * ``0`` if it contains binary data
        )delim"_doc)


    .def_prop_rw("key",
        nb::overload_cast<>(&ResourceVarFileInfo::key, nb::const_),
        nb::overload_cast<const std::string&>(&ResourceVarFileInfo::key),
        "Signature of the structure. Must be ``VarFileInfo``"_doc)

    .def_prop_rw("translations",
        nb::overload_cast<>(&ResourceVarFileInfo::translations),
        nb::overload_cast<std::vector<uint32_t>>(&ResourceVarFileInfo::translations),
        R"delim(
        List of languages that the application supports

        The **least** significant 16-bits  must contain a Microsoft language identifier,
        and the **most** significant 16-bits must contain the :class:`~lief.PE.CODE_PAGES`
        Either **most** or **least** 16-bits can be zero, indicating that the file is language or code page independent.
        )delim"_doc)

    LIEF_DEFAULT_STR(ResourceVarFileInfo);
}

}

