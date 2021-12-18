/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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

#include "LIEF/MachO/ParserConfig.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<>
void create<ParserConfig>(py::module& m) {

  py::class_<ParserConfig>(m, "ParserConfig", "Configuration of the MachO parser")
    .def(py::init<>())
    .def_readwrite("parse_dyld_exports",  &ParserConfig::parse_dyld_exports)
    .def_readwrite("parse_dyld_bindings", &ParserConfig::parse_dyld_bindings)
    .def_readwrite("parse_dyld_rebases",  &ParserConfig::parse_dyld_rebases)

    .def("full_dyldinfo",  &ParserConfig::full_dyldinfo)

    .def_property_readonly_static("deep",
      [] (py::object /* self */) { return ParserConfig::deep(); },
      "")

    .def_property_readonly_static("quick",
      [] (py::object /* self */) { return ParserConfig::quick(); },
      "");
}

}
}
