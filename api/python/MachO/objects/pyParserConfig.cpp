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
#include <string>

#include "LIEF/MachO/ParserConfig.hpp"

#include "pyMachO.hpp"

void init_MachO_ParserConfig_class(py::module& m) {

  py::class_<ParserConfig>(m, "ParserConfig", "Configuration of MachO's parser")
    .def(py::init<>())
    .def_property("parse_dyldinfo_deeply",
        static_cast<bool (ParserConfig::*)(void) const>(&ParserConfig::parse_dyldinfo_deeply),
        static_cast<ParserConfig& (ParserConfig::*)(bool)>(&ParserConfig::parse_dyldinfo_deeply),
        "If set to ``True``, parse deeply the " RST_CLASS_REF(lief.MachO.DyldInfo) " "
        "structure. It includes Exports, Bindings and Rebases")

    .def_property_readonly_static("deep",
      [] (py::object /* self */) { return ParserConfig::deep(); },
      "foobar")

    .def_property_readonly_static("quick",
      [] (py::object /* self */) { return ParserConfig::quick(); },
      "");







}
