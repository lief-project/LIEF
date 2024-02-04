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
#include "DEX/pyDEX.hpp"
#include "DEX/init.hpp"

#include "LIEF/DEX/Parser.hpp"
#include "LIEF/DEX/File.hpp"
#include "LIEF/DEX/Header.hpp"
#include "LIEF/DEX/Class.hpp"
#include "LIEF/DEX/Method.hpp"
#include "LIEF/DEX/Field.hpp"
#include "LIEF/DEX/Prototype.hpp"
#include "LIEF/DEX/Type.hpp"
#include "LIEF/DEX/MapList.hpp"
#include "LIEF/DEX/MapItem.hpp"
#include "LIEF/DEX/CodeInfo.hpp"

#define CREATE(X,Y) create<X>(Y)

namespace LIEF::DEX::py {
void init_objects(nb::module_& m) {
  CREATE(Parser, m);
  CREATE(File, m);
  CREATE(Header, m);
  CREATE(Class, m);
  CREATE(Method, m);
  CREATE(Field, m);
  CREATE(Prototype, m);
  CREATE(Type, m);
  CREATE(MapList, m);
  CREATE(MapItem, m);
  CREATE(CodeInfo, m);
}

void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("DEX", "Python API for DEX format");

  init_enums(mod);
  init_objects(mod);
  init_utils(mod);
}

}
