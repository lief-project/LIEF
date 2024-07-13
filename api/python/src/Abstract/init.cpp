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
#include "pyLIEF.hpp"
#include "Abstract/init.hpp"
#include "Abstract/enums.hpp"

#include "LIEF/Abstract/Header.hpp"
#include "LIEF/Abstract/Binary.hpp"
#include "LIEF/Abstract/Section.hpp"
#include "LIEF/Abstract/Symbol.hpp"
#include "LIEF/Abstract/Parser.hpp"
#include "LIEF/Abstract/Relocation.hpp"
#include "LIEF/Abstract/Function.hpp"
#include "LIEF/Abstract/DebugInfo.hpp"

#define CREATE(X,Y) create<X>(Y)

namespace LIEF::py {

void init_objects(nb::module_& m) {
  CREATE(Header, m);
  CREATE(Binary, m);
  CREATE(Section, m);
  CREATE(Symbol, m);
  CREATE(Parser, m);
  CREATE(Relocation, m);
  CREATE(Function, m);
  CREATE(DebugInfo, m);
}
void init_abstract(nb::module_& m) {
  init_enums(m);
  init_objects(m);
}
}
