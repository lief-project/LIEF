/* Copyright 2025 - 2026 R. Thomas
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
#include "COFF/pyCOFF.hpp"
#include "LIEF/COFF/ParserConfig.hpp"

namespace LIEF::COFF::py {

template<>
void create<ParserConfig>(nb::module_& m) {
  nb::class_<ParserConfig>(m, "ParserConfig",
      R"delim(
      )delim"_doc)
    .def(nb::init<>())
    .def_prop_ro_static("default_conf",
      [] (const nb::object& /* self */) { return ParserConfig::default_conf(); },
      "Default configuration"_doc)

    .def_prop_ro_static("all",
      [] (const nb::object& /* self */) { return ParserConfig::all(); },
      "All parsing options enabled"_doc);

}

}
