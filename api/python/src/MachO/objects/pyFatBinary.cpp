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
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

#include "LIEF/MachO/FatBinary.hpp"
#include "LIEF/MachO/Binary.hpp"

#include "pyIterator.hpp"
#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<FatBinary>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<FatBinary> fat(m, "FatBinary",
      R"delim(
      Class which represent a Mach-O (fat) binary
      This object is also used for representing Mach-O binaries that are **NOT FAT**
      )delim"_doc);

    init_ref_iterator<FatBinary::it_binaries>(fat, "it_binaries");

  fat
    .def_prop_ro("size", &FatBinary::size,
      "Number of " RST_CLASS_REF(lief.MachO.Binary) " registred"_doc)

    .def("at",
      nb::overload_cast<size_t>(&FatBinary::at),
      "Return the " RST_CLASS_REF(lief.MachO.Binary) " at the given index or None if it is not present"_doc,
      "index"_a,
      nb::rv_policy::reference_internal)

    .def("take",
        nb::overload_cast<Header::CPU_TYPE>(&FatBinary::take),
        "Return the " RST_CLASS_REF(lief.MachO.Binary) " that matches the "
        "given " RST_CLASS_REF(lief.MachO.Header.CPU_TYPE) ""_doc,
        "cpu"_a, nb::rv_policy::take_ownership)

    .def("write", &FatBinary::write,
        "Build a Mach-O universal binary"_doc,
        "filename"_a)

    .def("raw", &FatBinary::raw,
        "Build a Mach-O universal binary and return its bytes"_doc)

    .def("__len__", &FatBinary::size)

    .def("__getitem__",
        nb::overload_cast<size_t>(&FatBinary::operator[]),
        nb::rv_policy::reference_internal)

    .def("__iter__",
        nb::overload_cast<>(&FatBinary::begin),
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(FatBinary);

}
}
