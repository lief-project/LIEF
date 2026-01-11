/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#include "DyldSharedCache/pyDyldSharedCache.hpp"
#include "DyldSharedCache/init.hpp"

#include "LIEF/DyldSharedCache/utils.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include "nanobind/extra/stl/pathlike.h"

namespace LIEF::dsc::py {

void init_utils(nb::module_& m) {
  lief_mod->def("is_shared_cache",
    [] (nb::PathLike path) { return is_shared_cache(path); },
    "Check if the given file is a dyld shared cache"_doc,
    "file"_a
  );
}
}
