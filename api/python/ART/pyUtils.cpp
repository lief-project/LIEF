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
#include "pyART.hpp"

#include "LIEF/ART/utils.hpp"

namespace LIEF {
namespace ART {

void init_utils(py::module& m) {

  m.def("is_art",
      static_cast<bool (*)(const std::string&)>(&is_art),
      "Check if the **file** given in parameter is an ART",
      "path"_a);

  m.def("is_art",
      static_cast<bool (*)(const std::vector<uint8_t>&)>(&is_art),
      "Check if the **raw data** given in parameter is a ART",
      "raw"_a);

  m.def("version",
      static_cast<art_version_t (*)(const std::string&)>(&version),
      "Return the ART version of the **file** given in parameter",
      "file"_a);

  m.def("version",
      static_cast<art_version_t (*)(const std::vector<uint8_t>&)>(&version),
      "Return the ART version of the **raw data** given in parameter",
      "raw"_a);


  m.def("android_version",
      &android_version,
      "Return the " RST_CLASS_REF(lief.Android.ANDROID_VERSIONS) " associated with the given ART version ",
      "art_version"_a);
}

}
}

