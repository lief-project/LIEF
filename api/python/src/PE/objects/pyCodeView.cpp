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

#include "LIEF/PE/CodeView.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/array.h>

namespace LIEF::PE::py {

template<>
void create<CodeView>(nb::module_& m) {
  nb::class_<CodeView, LIEF::Object>(m, "CodeView")
    .def_prop_ro("cv_signature",
        nb::overload_cast<>(&CodeView::cv_signature, nb::const_),
        "Type of the code view (" RST_CLASS_REF(lief.PE.CODE_VIEW_SIGNATURES) ")"_doc)

    LIEF_DEFAULT_STR(LIEF::PE::CodeView);
}

}
