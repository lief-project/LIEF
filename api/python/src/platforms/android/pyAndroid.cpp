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
#include "LIEF/platforms/android/version.hpp"

#include "enums_wrapper.hpp"
#include "platforms/android/pyAndroid.hpp"
#include "pyLIEF.hpp"

#define PY_ENUM(x) to_string(x), x

namespace LIEF::Android::py {

void init_versions(nb::module_& m) {
  enum_<ANDROID_VERSIONS>(m, "ANDROID_VERSIONS")
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
      R"delim(
      Return the Android code associated with a :class:`~.ANDROID_VERSIONS`.

      For example: ``Nougat``
      )delim"_doc, "version"_a);

  m.def("version_string",
      &version_string,
      R"delim(
      Return the :class:`~.ANDROID_VERSIONS` as a string..

      For example: ``7.0.1``
      )delim"_doc, "version"_a);
}


void init_module(nb::module_& m) {
  nb::module_ android = m.def_submodule("Android", "Python API for Android platform");

  init_versions(android);
}
}
