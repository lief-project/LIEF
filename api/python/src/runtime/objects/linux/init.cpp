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
#include "runtime/objects/linux/init.hpp"
#include "runtime/pyRuntime.hpp"

namespace LIEF::runtime::Linux {
class Module;
class Host;
class Process;
}

namespace LIEF::runtime::Linux::py {
void init(nb::module_& m) {
  nb::module_ linux_mod = m.def_submodule("linux");

  create<LIEF::runtime::Linux::Module>(linux_mod);
  create<LIEF::runtime::Linux::Host>(linux_mod);
  create<LIEF::runtime::Linux::Process>(linux_mod);
}
}
