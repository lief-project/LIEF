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
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/RelocationDyld.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (RelocationDyld::*)(void) const;

template<class T>
using setter_t = void (RelocationDyld::*)(T);


template<>
void create<RelocationDyld>(py::module& m) {

  py::class_<RelocationDyld, Relocation>(m, "RelocationDyld",
      R"delim(
      Class that represents a relocation found in the :class:`~lief.MachO.DyldInfo` structure.

      While this class does not have an associated structure in the Mach-O format specification,
      it provides a convenient interface for the :attr:`lief.MachO.DyldInfo.rebase` values

      See also: :class:`~lief.MachO.RelocationObject`
      )delim")

    .def("__le__", &RelocationDyld::operator<=)
    .def("__lt__", &RelocationDyld::operator<)
    .def("__ge__", &RelocationDyld::operator>=)
    .def("__gt__", &RelocationDyld::operator>)
    .def("__eq__", &RelocationDyld::operator==)
    .def("__ne__", &RelocationDyld::operator!=)
    .def("__hash__",
        [] (const RelocationDyld& relocation) {
          return Hash::hash(relocation);
        })

    .def("__str__",
        [] (const RelocationDyld& relocation)
        {
          std::ostringstream stream;
          stream << relocation;
          std::string str = stream.str();
          return str;
        });

}

}
}
