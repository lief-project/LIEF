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
#include "OAT/pyOAT.hpp"
#include "OAT/init.hpp"

#include "LIEF/OAT/Parser.hpp"
#include "LIEF/OAT/Binary.hpp"
#include "LIEF/OAT/Header.hpp"
#include "LIEF/OAT/DexFile.hpp"
#include "LIEF/OAT/Class.hpp"
#include "LIEF/OAT/Method.hpp"

#define CREATE(X,Y) create<X>(Y)

namespace LIEF::OAT::py {

inline void init_objects(nb::module_& m) {
  CREATE(Parser, m);
  CREATE(Binary, m);
  CREATE(Header, m);
  CREATE(DexFile, m);
  CREATE(Class, m);
  CREATE(Method, m);
}

void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("OAT", "Python API for OAT format");

  init_enums(mod);
  init_utils(mod);

  init_objects(mod);
}


}
