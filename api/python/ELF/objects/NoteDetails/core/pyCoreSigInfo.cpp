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
#include "LIEF/ELF/NoteDetails/core/CoreSigInfo.hpp"


namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (CoreSigInfo::*)(void) const;

template<class T>
using setter_t = void (CoreSigInfo::*)(T);

template<>
void create<CoreSigInfo>(py::module& m) {

  py::class_<CoreSigInfo, NoteDetails>(m, "CoreSigInfo")

    .def_property("signo",
        static_cast<getter_t<int32_t>>(&CoreSigInfo::signo),
        static_cast<setter_t<int32_t>>(&CoreSigInfo::signo),
        "Signal number")

    .def_property("sigcode",
        static_cast<getter_t<int32_t>>(&CoreSigInfo::sigcode),
        static_cast<setter_t<int32_t>>(&CoreSigInfo::sigcode),
        "Signal code")

    .def_property("sigerrno",
        static_cast<getter_t<int32_t>>(&CoreSigInfo::sigerrno),
        static_cast<setter_t<int32_t>>(&CoreSigInfo::sigerrno),
        "If non-zero, an errno value associated with this signal")

    .def("__eq__", &CoreSigInfo::operator==)
    .def("__ne__", &CoreSigInfo::operator!=)
    .def("__hash__",
        [] (const CoreSigInfo& note) {
          return Hash::hash(note);
        })

    .def("__str__",
        [] (const CoreSigInfo& note)
        {
          std::ostringstream stream;
          stream << note;
          std::string str = stream.str();
          return str;
        });


}
} // namespace ELF
} // namespace LIEF
