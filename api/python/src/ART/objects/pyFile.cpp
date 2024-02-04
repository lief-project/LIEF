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
#include "LIEF/ART/File.hpp"

#include "ART/pyART.hpp"

#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::ART::py {

template<>
void create<File>(nb::module_& m) {
  nb::class_<File, LIEF::Object>(m, "File", "ART File representation"_doc)

    .def_prop_ro("header",
        nb::overload_cast<>(&File::header),
        "Return the ART " RST_CLASS_REF(lief.ART.Header) ""_doc,
        nb::rv_policy::reference_internal)
    LIEF_DEFAULT_STR(Header);
}

}
