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
#include "LIEF/ART/File.hpp"
#include "LIEF/ART/hash.hpp"

#include "pyART.hpp"

namespace LIEF {
namespace ART {

template<class T>
using no_const_getter = T (File::*)(void);

template<class T, class P>
using no_const_func = T (File::*)(P);

template<class T>
using getter_t = T (File::*)(void) const;

template<class T>
using setter_t = void (File::*)(T);

template<>
void create<File>(py::module& m) {

  // File object
  py::class_<File, LIEF::Object>(m, "File", "ART File representation")

    .def_property_readonly("header",
        static_cast<no_const_getter<Header&>>(&File::header),
        "Return the ART " RST_CLASS_REF(lief.ART.Header) "",
        py::return_value_policy::reference)

    .def("__eq__", &File::operator==)
    .def("__ne__", &File::operator!=)
    .def("__hash__",
        [] (const File& file) {
          return Hash::hash(file);
        })

    .def("__str__",
        [] (const File& file)
        {
          std::ostringstream stream;
          stream << file;
          std::string str = stream.str();
          return str;
        });
}

}
}
