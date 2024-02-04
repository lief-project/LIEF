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

#include "LIEF/PE/debug/CodeView.hpp"
#include "enums_wrapper.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/array.h>

#define PY_ENUM(x) to_string(x), x

namespace LIEF::PE::py {

template<>
void create<CodeView>(nb::module_& m) {
  nb::class_<CodeView, Debug> cv(m, "CodeView");

  enum_<CodeView::SIGNATURES>(cv, "SIGNATURES")
    .value(PY_ENUM(CodeView::SIGNATURES::UNKNOWN))
    .value(PY_ENUM(CodeView::SIGNATURES::PDB_70))
    .value(PY_ENUM(CodeView::SIGNATURES::PDB_20))
    .value(PY_ENUM(CodeView::SIGNATURES::CV_50))
    .value(PY_ENUM(CodeView::SIGNATURES::CV_41));
  cv
    .def(nb::init<>())
    .def(nb::init<CodeView::SIGNATURES>())
    .def_prop_ro("cv_signature",
        nb::overload_cast<>(&CodeView::signature, nb::const_),
        "Type of the code view (" RST_CLASS_REF(lief.PE.CodeView.SIGNATURES) ")"_doc)

    LIEF_DEFAULT_STR(CodeView);
}

}
