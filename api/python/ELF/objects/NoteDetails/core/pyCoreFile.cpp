/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include <vector>

#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreFile.hpp"

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (CoreFile::*)(void) const;

template<class T>
using setter_t = void (CoreFile::*)(T);

template<>
void create<CoreFile>(py::module& m) {

  py::class_<CoreFile, NoteDetails>(m, "CoreFile")

    .def_property_readonly("count",
        &CoreFile::count,
        "Number of files mapped in core"
        )

	.def_property("files",
        static_cast<getter_t<std::vector<CoreFileEntry>>>(&CoreFile::files),
        static_cast<setter_t<const std::vector<CoreFileEntry>&>>(&CoreFile::files),
        "List of files mapped in core")

    .def("__eq__", &CoreFile::operator==)
    .def("__ne__", &CoreFile::operator!=)
    .def("__hash__",
        [] (const CoreFile& note) {
          return Hash::hash(note);
        })

    .def("__str__",
        [] (const CoreFile& note)
        {
          std::ostringstream stream;
          stream << note;
          std::string str = stream.str();
          return str;
        });
}

}
}
