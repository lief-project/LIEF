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
#include "VDEX/pyVDEX.hpp"
#include "VDEX/init.hpp"

#include <LIEF/VDEX/Parser.hpp>
#include <LIEF/VDEX/File.hpp>
#include <LIEF/VDEX/Header.hpp>

#define CREATE(X,Y) create<X>(Y)

namespace LIEF::VDEX::py {

inline void init_objects(nb::module_& m) {
  CREATE(Parser, m);
  CREATE(File, m);
  CREATE(Header, m);
}

void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("VDEX", "Python API for VDEX format"_doc);

  init_objects(mod);
  init_utils(mod);
}
}
