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
#include "LIEF/OAT/utils.hpp"
#include "pyOAT.hpp"

namespace LIEF {
namespace OAT {

void init_utils(py::module& m) {
  m.def("is_oat", static_cast<bool (*)(const LIEF::ELF::Binary&)>(&is_oat),
        "Check if the " RST_CLASS_REF(
            lief.ELF.Binary) " given in parameter is a OAT one",
        "binary"_a);

  m.def("is_oat", static_cast<bool (*)(const std::string&)>(&is_oat),
        "Check if the **file** given in parameter is a OAT one", "path"_a);

  m.def("is_oat", static_cast<bool (*)(const std::vector<uint8_t>&)>(&is_oat),
        "Check if the **raw data** given in parameter is a OAT one", "raw"_a);

  m.def("version",
        static_cast<oat_version_t (*)(const LIEF::ELF::Binary&)>(&version),
        "Return the OAT version of the " RST_CLASS_REF(
            lief.ELF.Binary) " given in parameter",
        "binary"_a);

  m.def("version", static_cast<oat_version_t (*)(const std::string&)>(&version),
        "Return the OAT version of the **file** given in parameter", "file"_a);

  m.def("version",
        static_cast<oat_version_t (*)(const std::vector<uint8_t>&)>(&version),
        "Return the OAT version of the **raw data** given in parameter",
        "raw"_a);

  m.def("android_version", &android_version,
        "Return the " RST_CLASS_REF(
            lief.Android
                .ANDROID_VERSIONS) " associated with the given OAT version");
}

}  // namespace OAT
}  // namespace LIEF
