/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#include "LIEF/config.h"
#include "pyLIEF.hpp"
#include "pyIterators.hpp"

#include "LIEF/PE/signature/types.hpp"

void init_LIEF_iterators(py::module& m) {
  // Abstract
  // ========
  init_ref_iterator<LIEF::it_sections>(m, "it_sections");
  init_ref_iterator<LIEF::it_symbols>(m, "it_symbols");
  init_ref_iterator<LIEF::it_relocations>(m, "it_relocations");
}
