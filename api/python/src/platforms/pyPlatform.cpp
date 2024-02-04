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
#include "platforms/pyPlatform.hpp"
#include "LIEF/platforms.hpp"
#include "enums_wrapper.hpp"
#include "pyLIEF.hpp"
#include "platforms/android/pyAndroid.hpp"

namespace LIEF::py {

void init_platforms(nb::module_& m) {
  LIEF::enum_<PLATFORMS>(m, "PLATFORMS")
    .value("UNKNOWN", PLATFORMS::UNKNOWN)
    .value("LINUX",   PLATFORMS::LINUX)
    .value("ANDROID", PLATFORMS::ANDROID_PLAT)
    .value("WINDOWS", PLATFORMS::WINDOWS)
    .value("IOS",     PLATFORMS::IOS)
    .value("OSX",     PLATFORMS::OSX);

  m.def("current_platform", &current_platform,
      "Return the current plaform (Linux, Windows, ...) as a :attr:`lief.PLATFORMS` enum"_doc);

  LIEF::Android::py::init_module(m);
}

}
