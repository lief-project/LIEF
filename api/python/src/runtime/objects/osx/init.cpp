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
#include "runtime/objects/osx/init.hpp"
#include "runtime/pyRuntime.hpp"

namespace LIEF::runtime::osx {
class Module;
class Host;
class Process;
}

namespace LIEF::runtime::osx::py {
void init(nb::module_& m) {
  nb::module_ osx_mod = m.def_submodule("osx");

  create<LIEF::runtime::osx::Module>(osx_mod);
  create<LIEF::runtime::osx::Host>(osx_mod);
  create<LIEF::runtime::osx::Process>(osx_mod);
}
}
