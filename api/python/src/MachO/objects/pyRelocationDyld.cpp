/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include <nanobind/stl/string.h>

#include "LIEF/MachO/RelocationDyld.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<RelocationDyld>(nb::module_& m) {

  nb::class_<RelocationDyld, Relocation>(m, "RelocationDyld",
      R"delim(
      Class that represents a relocation found in the :class:`~lief.MachO.DyldInfo` structure.

      While this class does not have an associated structure in the Mach-O format specification,
      it provides a convenient interface for the :attr:`lief.MachO.DyldInfo.rebase` values

      See also: :class:`~lief.MachO.RelocationObject`
      )delim"_doc)

    .def("__le__", nb::overload_cast<const RelocationDyld&>(&RelocationDyld::operator<=, nb::const_))
    .def("__lt__", nb::overload_cast<const RelocationDyld&>(&RelocationDyld::operator<, nb::const_))
    .def("__ge__", nb::overload_cast<const RelocationDyld&>(&RelocationDyld::operator>=, nb::const_))
    .def("__gt__", nb::overload_cast<const RelocationDyld&>(&RelocationDyld::operator>, nb::const_))

    LIEF_DEFAULT_STR(RelocationDyld);


}
}
