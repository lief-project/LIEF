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

#include <string>
#include <sstream>


void init_ELF_Builder_class(py::module& m) {
  py::class_<Builder>(m, "Builder")
    .def(py::init<Binary*>())

    .def("build", static_cast<void (Builder::*)(void)>(&Builder::build))

    .def("empties_gnuhash",
        &Builder::empties_gnuhash,
        py::return_value_policy::reference)

    .def("write",
        &Builder::write)

    .def("get_build",
        &Builder::get_build,
        py::return_value_policy::reference_internal);

}
