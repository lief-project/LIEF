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
#include "pyOAT.hpp"

namespace LIEF {
namespace OAT {

void init_python_module(py::module& m) {
  py::module LIEF_OAT_module = m.def_submodule("OAT", "Python API for OAT format");

  init_enums(LIEF_OAT_module);
  init_utils(LIEF_OAT_module);

  init_objects(LIEF_OAT_module);
}


void init_objects(py::module& m) {
  CREATE(Parser, m);
  CREATE(Binary, m);
  CREATE(Header, m);
  CREATE(DexFile, m);
  CREATE(Class, m);
  CREATE(Method, m);
}
}
}
