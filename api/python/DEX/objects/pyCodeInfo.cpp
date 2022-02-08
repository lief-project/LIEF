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
#include "LIEF/DEX/CodeInfo.hpp"
#include "LIEF/DEX/hash.hpp"

#include "pyDEX.hpp"

namespace LIEF {
namespace DEX {

template<class T>
using getter_t = T (CodeInfo::*)(void) const;

template<class T>
using no_const_getter_t = T (CodeInfo::*)(void);

template<class T>
using setter_t = void (CodeInfo::*)(T);


template<>
void create<CodeInfo>(py::module& m) {

  py::class_<CodeInfo, LIEF::Object>(m, "CodeInfo", "DEX CodeInfo representation")

    .def("__eq__", &CodeInfo::operator==)
    .def("__ne__", &CodeInfo::operator!=)
    .def("__hash__",
        [] (const CodeInfo& cinfo) {
          return Hash::hash(cinfo);
        })

    .def("__str__",
        [] (const CodeInfo& cinfo) {
          std::ostringstream stream;
          stream << cinfo;
          return stream.str();
        });
}

}
}
