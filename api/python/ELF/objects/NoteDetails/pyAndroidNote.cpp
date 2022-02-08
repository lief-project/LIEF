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
#include "LIEF/ELF/NoteDetails/AndroidNote.hpp"

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (AndroidNote::*)(void) const;

template<class T>
using setter_t = void (AndroidNote::*)(T);

template<>
void create<AndroidNote>(py::module& m) {

  py::class_<AndroidNote, NoteDetails>(m, "AndroidNote")

    .def_property("sdk_version",
        static_cast<getter_t<uint32_t>>(&AndroidNote::sdk_version),
        static_cast<setter_t<uint32_t>>(&AndroidNote::sdk_version),
        "Target SDK platform"
        )

    .def_property("ndk_version",
        static_cast<getter_t<std::string>>(&AndroidNote::ndk_version),
        static_cast<setter_t<const std::string&>>(&AndroidNote::ndk_version),
        "Android NDK version used to build the current binary"
        )

    .def_property("ndk_build_number",
        static_cast<getter_t<std::string>>(&AndroidNote::ndk_build_number),
        static_cast<setter_t<const std::string&>>(&AndroidNote::ndk_build_number),
        "Android NDK build number"
        )

    .def("__eq__", &AndroidNote::operator==)
    .def("__ne__", &AndroidNote::operator!=)
    .def("__hash__",
        [] (const AndroidNote& note) {
          return Hash::hash(note);
        })

    .def("__str__",
        [] (const AndroidNote& note)
        {
          std::ostringstream stream;
          stream << note;
          std::string str = stream.str();
          return str;
        });
}

}
}
