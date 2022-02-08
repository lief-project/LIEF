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
#include "pyVDEX.hpp"


namespace LIEF {
namespace VDEX {
void init_python_module(py::module& m) {
  py::module LIEF_VDEX_module = m.def_submodule("VDEX", "Python API for VDEX format");

  init_objects(LIEF_VDEX_module);
  init_utils(LIEF_VDEX_module);
}


void init_objects(py::module& m) {
  CREATE(Parser, m);
  CREATE(File, m);
  CREATE(Header, m);
}

}
}
