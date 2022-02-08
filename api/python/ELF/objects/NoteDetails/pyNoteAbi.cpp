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
#include "LIEF/ELF/NoteDetails/NoteAbi.hpp"

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (NoteAbi::*)(void) const;

template<class T>
using setter_t = void (NoteAbi::*)(T);

template<>
void create<NoteAbi>(py::module& m) {

  py::class_<NoteAbi, NoteDetails>(m, "NoteAbi")

    .def_property_readonly("abi",
        static_cast<getter_t<NOTE_ABIS>>(&NoteAbi::abi),
        "Return the target " RST_CLASS_REF(lief.ELF.NOTE_ABIS) ""
        )

    .def_property_readonly("version",
        static_cast<getter_t<NoteAbi::version_t>>(&NoteAbi::version),
        "Return the target version as ``(Major, Minor, Patch)``"
        )

    .def("__eq__", &NoteAbi::operator==)
    .def("__ne__", &NoteAbi::operator!=)
    .def("__hash__",
        [] (const NoteAbi& note) {
          return Hash::hash(note);
        })

    .def("__str__",
        [] (const NoteAbi& note)
        {
          std::ostringstream stream;
          stream << note;
          std::string str = stream.str();
          return str;
        });
}

}
}
