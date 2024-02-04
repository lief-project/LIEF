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
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

#include "LIEF/MachO/TwoLevelHints.hpp"

#include "MachO/pyMachO.hpp"
#include "nanobind/extra/memoryview.hpp"
#include "pyIterator.hpp"

namespace LIEF::MachO::py {
template<>
void create<TwoLevelHints>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<TwoLevelHints, LoadCommand> cmd(m, "TwoLevelHints",
    R"delim(Class which represents the `LC_TWOLEVEL_HINTS` command)delim"_doc);

  init_ref_iterator<TwoLevelHints::it_hints_t>(cmd, "it_hints_t");

  cmd
    .def_prop_ro("hints", nb::overload_cast<>(&TwoLevelHints::hints))
    .def_prop_ro("content",
        [] (const TwoLevelHints& self) {
          const span<const uint8_t> content = self.content();
          return nb::memoryview::from_memory(content.data(), content.size());
        }, "The original content as a bytes stream"_doc)

  LIEF_DEFAULT_STR(TwoLevelHints);

}
}
