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
#include "PE/pyPE.hpp"
#include "LIEF/PE/debug/Repro.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/extra/memoryview.hpp>
#include "nanobind/utils.hpp"

namespace LIEF::PE::py {

template<>
void create<Repro>(nb::module_& m) {
  nb::class_<Repro, Debug>(m, "Repro",
    R"delim(
    This class represents a reproducible build entry from the debug directory.
    (``IMAGE_DEBUG_TYPE_REPRO``).
    This entry is usually generated with the undocumented `/Brepro` linker flag.

    See: https://nikhilism.com/post/2020/windows-deterministic-builds/
    )delim"_doc)
    .def_prop_rw("hash",
        [] (const Repro& repro) {
          return nb::to_memoryview(repro.hash());
        },
        [] (Repro& repro, nb::bytes bytes) {
          repro.hash(nb::to_vector(bytes));
        }, "The hash associated with the reproducible build"_doc)
    LIEF_DEFAULT_STR(Repro);
}
}
