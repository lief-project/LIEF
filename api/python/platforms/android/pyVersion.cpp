/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "pyAndroid.hpp"
#include "LIEF/platforms/android/version.hpp"

#define PY_ENUM(x) to_string(x), x

namespace LIEF {
namespace Android {

void init_versions(py::module& m) {
  py::enum_<ANDROID_VERSIONS>(m, "ANDROID_VERSIONS")
    .value(PY_ENUM(ANDROID_VERSIONS::VERSION_UNKNOWN))
    .value(PY_ENUM(ANDROID_VERSIONS::VERSION_601))
    .value(PY_ENUM(ANDROID_VERSIONS::VERSION_700))
    .value(PY_ENUM(ANDROID_VERSIONS::VERSION_710))
    .value(PY_ENUM(ANDROID_VERSIONS::VERSION_712))
    .value(PY_ENUM(ANDROID_VERSIONS::VERSION_800))
    .value(PY_ENUM(ANDROID_VERSIONS::VERSION_810))
    .value(PY_ENUM(ANDROID_VERSIONS::VERSION_900));

  m.def("code_name",
      &code_name,
      "Return the Android code associated with a " RST_CLASS_REF(lief.Android.ANDROID_VERSIONS) ".\n"

      "For example: ``Nougat``",
      "version"_a);

  m.def("version_string",
      &version_string,
      "Return the " RST_CLASS_REF(lief.Android.ANDROID_VERSIONS) " as a string.\n"

      "For example: ``7.0.1``",
      "version"_a);
}

}
}
