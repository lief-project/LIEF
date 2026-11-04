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
#include "runtime/objects/android/init.hpp"
#include "runtime/pyRuntime.hpp"

namespace LIEF::runtime::android {
class Module;
class Host;
class Process;
class Property;
}

namespace LIEF::runtime::android::py {
void init(nb::module_& m) {
  nb::module_ android_mod = m.def_submodule("android");

  create<LIEF::runtime::android::Module>(android_mod);
  create<LIEF::runtime::android::Host>(android_mod);
  create<LIEF::runtime::android::Property>(android_mod);
  create<LIEF::runtime::android::Process>(android_mod);
}
}
