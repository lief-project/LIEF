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


#include "pyELF.hpp"

#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Builder.hpp"

namespace LIEF {
namespace ELF {

template<>
void create<Builder>(py::module& m) {
  py::class_<Builder> builder(m, "Builder",
      R"delim(
      Class which takes an :class:`lief.ELF.Binary` object and reconstructs a valid binary
      )delim");

  py::class_<Builder::config_t>(builder, "config_t",
                                "Interface to tweak the " RST_CLASS_REF(lief.ELF.Builder) "")
    .def(py::init<>())
    .def_readwrite("force_relocations", &Builder::config_t::force_relocations,
                   "Force to relocate all the ELF structures that can be relocated (mostly for testing)");

  builder
    .def(py::init<Binary&>(),
        "Constructor that takes a " RST_CLASS_REF(lief.ELF.Binary) "",
        "elf_binary"_a)

    .def("build",
        static_cast<void (Builder::*)(void)>(&Builder::build),
        "Perform the build of the provided ELF binary")

    .def("set_config",
        &Builder::set_config,
        "Tweak the ELF builder with the provided config parameter")

    .def("force_relocations",
        &Builder::force_relocations,
        "Force relocating all the ELF characteristics supported by LIEF"
        "flag"_a = true,
        py::return_value_policy::reference_internal)

    .def("write",
        &Builder::write,
        "Write the build result into the ``output`` file",
        "output"_a)

    .def("get_build",
        &Builder::get_build,
        "Return the build result as a ``list`` of bytes",
        py::return_value_policy::reference_internal);

}
}
}
