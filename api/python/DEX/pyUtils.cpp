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
#include "pyDEX.hpp"

#include "LIEF/DEX/utils.hpp"

namespace LIEF {
namespace DEX {

void init_utils(py::module& m) {

  m.def("is_dex",
      static_cast<bool (*)(const std::string&)>(&is_dex),
      "Check if the **file** given in parameter is a DEX",
      "path"_a);

  m.def("is_dex",
      static_cast<bool (*)(const std::vector<uint8_t>&)>(&is_dex),
      "Check if the **raw data** given in parameter is a DEX",
      "raw"_a);

  m.def("version",
      static_cast<dex_version_t (*)(const std::string&)>(&version),
      "Return the DEX version of the **file** given in parameter",
      "file"_a);

  m.def("version",
      static_cast<dex_version_t (*)(const std::vector<uint8_t>&)>(&version),
      "Return the DEX version of the **raw data** given in parameter",
      "raw"_a);

}

}
}

