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
#include "LIEF/PE/CodeViewPDB.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (CodeViewPDB::*)(void) const;

template<class T>
using setter_t = void (CodeViewPDB::*)(T);


template<>
void create<CodeViewPDB>(py::module& m) {
  py::class_<CodeViewPDB, CodeView>(m, "CodeViewPDB")
    .def(py::init<>())

    .def_property("signature",
        static_cast<getter_t<CodeViewPDB::signature_t>>(&CodeViewPDB::signature),
        static_cast<setter_t<CodeViewPDB::signature_t>>(&CodeViewPDB::signature))

    .def_property("age",
        static_cast<getter_t<uint32_t>>(&CodeViewPDB::age),
        static_cast<setter_t<uint32_t>>(&CodeViewPDB::age))

    .def_property("filename",
        static_cast<getter_t<const std::string&>>(&CodeViewPDB::filename),
        static_cast<setter_t<const std::string&>>(&CodeViewPDB::filename))

    .def("__eq__", &CodeViewPDB::operator==)
    .def("__ne__", &CodeViewPDB::operator!=)
    .def("__hash__",
        [] (const CodeViewPDB& codeview) {
          return Hash::hash(codeview);
        })

    .def("__str__", [] (const CodeViewPDB& cv)
        {
          std::ostringstream stream;
          stream << cv;
          return stream.str();
        });
}

}
}
