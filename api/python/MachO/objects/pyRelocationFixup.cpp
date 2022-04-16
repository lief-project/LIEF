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
#include "LIEF/MachO/RelocationFixup.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (RelocationFixup::*)() const;

template<class T>
using setter_t = void (RelocationFixup::*)(T);


template<>
void create<RelocationFixup>(py::module& m) {

  py::class_<RelocationFixup, Relocation>(m, "RelocationFixup",
      R"delim(
      Class that represents a rebase relocation found in the LC_DYLD_CHAINED_FIXUPS command.

      This class extends :class:`lief.Relocation` (and :class:`lief.MachO.Relocation`) in which
      :attr:`~lief.Relocation.address` is set to the absolute virtual address
      where the relocation must take place (e.g. `0x10000d270`).

      On the other hand, :attr:`~lief.MachO.RelocationFixup.target` contains the value
      that should be set at :attr:`~lief.Relocation.address` if the
      imagebase is :attr:`~lief.Binary.imagebase` (e.g. `0x1000073a8`).

      If the Mach-O loader chooses another base address (like 0x7ff100000), it must set
      `0x10000d270` to `0x7ff1073a8`.
      )delim")

    .def_property("target",
        py::overload_cast<>(&RelocationFixup::target, py::const_),
        py::overload_cast<uint64_t>(&RelocationFixup::target))

    .def("__eq__", &RelocationFixup::operator==)
    .def("__ne__", &RelocationFixup::operator!=)
    .def("__hash__",
        [] (const RelocationFixup& relocation) {
          return Hash::hash(relocation);
        })

    .def("__str__",
        [] (const RelocationFixup& relocation) {
          std::ostringstream stream;
          std::string str = stream.str();
          return stream.str();
        });

}

}
}
