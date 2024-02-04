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
#include "ART/pyART.hpp"
#include "ART/init.hpp"

#include "LIEF/ART/Parser.hpp"
#include "LIEF/ART/File.hpp"
#include "LIEF/ART/Header.hpp"
#include "LIEF/ART/enums.hpp"
#include "LIEF/ART/EnumToString.hpp"

#define CREATE(X,Y) create<X>(Y)

#define PY_ENUM(x) to_string(x), x

namespace LIEF::ART::py {

inline void init_objects(nb::module_& m) {
  CREATE(Parser, m);
  CREATE(File, m);
  CREATE(Header, m);
}

inline void init_enums(nb::module_& m) {
  nb::enum_<STORAGE_MODES>(m, "STORAGE_MODES")
    .value(PY_ENUM(STORAGE_MODES::STORAGE_UNCOMPRESSED))
    .value(PY_ENUM(STORAGE_MODES::STORAGE_LZ4))
    .value(PY_ENUM(STORAGE_MODES::STORAGE_LZ4HC));
}

void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("ART", "Python API for ART format");

  init_enums(mod);
  init_objects(mod);
  init_utils(mod);
}
}
