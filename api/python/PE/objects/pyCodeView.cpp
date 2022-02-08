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

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/CodeView.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (CodeView::*)(void) const;

template<class T>
using setter_t = void (CodeView::*)(T);


template<>
void create<CodeView>(py::module& m) {
  py::class_<CodeView, LIEF::Object>(m, "CodeView")
    .def_property_readonly("cv_signature",
        static_cast<getter_t<CODE_VIEW_SIGNATURES>>(&CodeView::cv_signature),
        "Type of the code view (" RST_CLASS_REF(lief.PE.CODE_VIEW_SIGNATURES) ")")

    .def("__eq__", &CodeView::operator==)
    .def("__ne__", &CodeView::operator!=)
    .def("__hash__",
        [] (const CodeView& codeview) {
          return Hash::hash(codeview);
        })

    .def("__str__", [] (const CodeView& cv)
        {
          std::ostringstream stream;
          stream << cv;
          return stream.str();
        });
}

}
}
