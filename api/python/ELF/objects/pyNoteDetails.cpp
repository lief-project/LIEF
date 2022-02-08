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
#include <string>
#include <sstream>

#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/NoteDetails.hpp"

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (NoteDetails::*)(void) const;

template<class T>
using setter_t = void (NoteDetails::*)(T);


template<>
void create<NoteDetails>(py::module& m) {

  py::class_<NoteDetails, LIEF::Object>(m, "NoteDetails")
    .def(py::init<>(),
        "Default ctor")

    .def("__eq__", &NoteDetails::operator==)
    .def("__ne__", &NoteDetails::operator!=)
    .def("__hash__",
        [] (const NoteDetails& note) {
          return Hash::hash(note);
        })

    .def("__str__",
        [] (const NoteDetails& note)
        {
          std::ostringstream stream;
          stream << note;
          std::string str = stream.str();
          return str;
        });
}

}
}
