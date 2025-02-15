/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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

#include "LIEF/PE/resources/ResourceVarFileInfo.hpp"
#include "LIEF/PE/resources/ResourceVar.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/extra/stl/u16string.h>

namespace LIEF::PE::py {

template<>
void create<ResourceVarFileInfo>(nb::module_& m) {
  nb::class_<ResourceVarFileInfo, LIEF::Object> obj(m, "ResourceVarFileInfo",
    R"doc(
    Representation of the ``VarFileInfo`` structure

    This structure represents the organization of data in a file-version resource.
    It contains version information not dependent on a particular language and
    code page combination.

    See: https://learn.microsoft.com/en-us/windows/win32/menurc/varfileinfo
    )doc"_doc
  );
  LIEF::py::init_ref_iterator<ResourceVarFileInfo::it_vars>(obj, "it_vars");

  obj
    .def_prop_ro("type", nb::overload_cast<>(&ResourceVarFileInfo::type, nb::const_),
      R"doc(
      The type of data in the version resource:
        * ``1`` if it contains text data
        * ``0`` if it contains binary data
      )doc"_doc
    )

    .def_prop_ro("key", nb::overload_cast<>(&ResourceVarFileInfo::key_u8, nb::const_),
      R"doc(Signature of the structure. Must be the unicode string "VarFileInfo")doc"_doc
    )

    .def_prop_ro("vars", nb::overload_cast<>(&ResourceVarFileInfo::vars),
      R"doc(Iterator over the embedded variables associated to the structure)doc"_doc
    )

    LIEF_DEFAULT_STR(ResourceVarFileInfo);


}

}

