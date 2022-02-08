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

#include "LIEF/MachO/FatBinary.hpp"

#include "pyIterators.hpp"
#include "pyMachO.hpp"


namespace LIEF {
namespace MachO {

template<>
void create<FatBinary>(py::module& m) {


  py::class_<FatBinary> fat(m, "FatBinary",
      R"delim(
      Class which represent a Mach-O (fat) binary
      This object is also used for representing Mach-O binaries that are **NOT FAT**
      )delim");

    init_ref_iterator<FatBinary::it_binaries>(fat, "it_binaries");

  fat
    .def_property_readonly("size",
      &FatBinary::size,
      "Number of " RST_CLASS_REF(lief.MachO.Binary) " registred")

    .def("at",
      static_cast<Binary* (FatBinary::*)(size_t)>(&FatBinary::at),
      "Return the " RST_CLASS_REF(lief.MachO.Binary) " at the given index or None if it is not present",
      "index"_a,
      py::return_value_policy::reference_internal)

    .def("take",
        static_cast<std::unique_ptr<Binary>(FatBinary::*)(CPU_TYPES)>(&FatBinary::take),
        "Return the " RST_CLASS_REF(lief.MachO.Binary) " that matches the "
        "given " RST_CLASS_REF(lief.MachO.CPU_TYPES) "",
        "cpu"_a,
        py::return_value_policy::take_ownership)

    .def("write",
        &FatBinary::write,
        "Build a Mach-O universal binary",
        "filename"_a)

    .def("raw",
        &FatBinary::raw,
        "Build a Mach-O universal binary and return its bytes")

    .def("__len__",
        &FatBinary::size)

    .def("__getitem__",
        static_cast<Binary* (FatBinary::*)(size_t)>(&FatBinary::operator[]),
        "",
        py::return_value_policy::reference_internal)

    .def("__iter__",
        static_cast<FatBinary::it_binaries (FatBinary::*)(void)>(&FatBinary::begin),
        py::return_value_policy::reference_internal)

    .def("__str__",
        [] (const FatBinary& fat_binary)
        {
          std::ostringstream stream;
          stream << fat_binary;
          std::string str = stream.str();
          return str;
        });

}

}
}
