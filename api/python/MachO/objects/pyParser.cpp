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
#include <memory>

#include "LIEF/MachO/Parser.hpp"

#include "pyMachO.hpp"

void init_MachO_Parser_class(py::module& m) {

  // Parser (Parser)
  m.def("parse",
    static_cast<std::vector<Binary*> (*) (const std::string&)>(&LIEF::MachO::Parser::parse),
    "Parse the given binary and return a **list** of " RST_CLASS_REF(lief.MachO.Binary) " objects",
    "filename"_a,
    py::return_value_policy::take_ownership);


  m.def("parse",
    static_cast<std::vector<Binary*> (*) (const std::vector<uint8_t>&, const std::string&)>(&LIEF::MachO::Parser::parse),
    "Parse the given binary (from raw) and return a **list** of " RST_CLASS_REF(lief.MachO.Binary) " objects",
    py::arg("raw"), py::arg("name") = "",
    py::return_value_policy::take_ownership);


}
