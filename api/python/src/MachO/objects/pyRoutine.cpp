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

#include "LIEF/MachO/Routine.hpp"

#include "MachO/pyMachO.hpp"

#include "nanobind/stl/string.h"

namespace LIEF::MachO::py {

template<>
void create<Routine>(nb::module_& m) {

  nb::class_<Routine, LoadCommand>(m, "Routine",
      R"delim(
      Class that represents the ``LC_ROUTINE/LC_ROUTINE64`` commands.
      Accodring to the Mach-O ``loader.h`` documentation:

      > The routines command contains the address of the dynamic shared library
      > initialization routine and an index into the module table for the module
      > that defines the routine. Before any modules are used from the library the
      > dynamic linker fully binds the module that defines the initialization routine
      > and then calls it. This gets called before any module initialization
      > routines (used for C++ static constructors) in the library.
      )delim"_doc)

    .def_prop_rw("init_address",
        nb::overload_cast<>(&Routine::init_address, nb::const_),
        nb::overload_cast<uint64_t>(&Routine::init_address),
        "Address of initialization routine"_doc)

    .def_prop_rw("init_module",
        nb::overload_cast<>(&Routine::init_module, nb::const_),
        nb::overload_cast<uint64_t>(&Routine::init_module),
        "Index into the module table that the init routine is defined in"_doc)

    .def_prop_rw("reserved1",
        nb::overload_cast<>(&Routine::reserved1, nb::const_),
        nb::overload_cast<uint64_t>(&Routine::reserved1))

    .def_prop_rw("reserved2",
        nb::overload_cast<>(&Routine::reserved2, nb::const_),
        nb::overload_cast<uint64_t>(&Routine::reserved2))

    .def_prop_rw("reserved3",
        nb::overload_cast<>(&Routine::reserved3, nb::const_),
        nb::overload_cast<uint64_t>(&Routine::reserved3))

    .def_prop_rw("reserved4",
        nb::overload_cast<>(&Routine::reserved4, nb::const_),
        nb::overload_cast<uint64_t>(&Routine::reserved4))

    .def_prop_rw("reserved5",
        nb::overload_cast<>(&Routine::reserved5, nb::const_),
        nb::overload_cast<uint64_t>(&Routine::reserved5))

    .def_prop_rw("reserved6",
        nb::overload_cast<>(&Routine::reserved6, nb::const_),
        nb::overload_cast<uint64_t>(&Routine::reserved6))

    LIEF_DEFAULT_STR(Routine);
}
}
