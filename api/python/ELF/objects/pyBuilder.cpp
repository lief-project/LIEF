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


#include "pyELF.hpp"

#include "LIEF/ELF/Builder.hpp"

namespace LIEF {
namespace ELF {

template<>
void create<Builder>(py::module& m) {
  py::class_<Builder>(m, "Builder")
    .def(py::init<Binary*>(),
        "Constructor that takes a " RST_CLASS_REF(lief.ELF.Binary) "",
        "elf_binary"_a)

    .def("build",
        static_cast<void (Builder::*)(void)>(&Builder::build),
        "Perform the build process")

    .def("empties_gnuhash",
        &Builder::empties_gnuhash,
        "Disable the " RST_CLASS_REF(lief.ELF.GnuHash) "",
        py::return_value_policy::reference)

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
