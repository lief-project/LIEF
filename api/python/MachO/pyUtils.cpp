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
#include "LIEF/MachO/utils.hpp"
#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

void init_utils(py::module& m) {
  m.def("is_macho", static_cast<bool (*)(const std::string&)>(&is_macho),
        "Check if the given file is a ``MachO`` (from filename)", "filename"_a);

  m.def("is_macho",
        static_cast<bool (*)(const std::vector<uint8_t>&)>(&is_macho),
        "Check if the given raw data is a ``MachO``", "raw"_a);

  m.def("is_fat", &is_fat, "Check if the given Mach-O is fat", "file"_a);

  m.def("is_64", &is_64, "Check if the given Mach-O is 64-bits", "file"_a);

  m.def(
      "check_layout",
      [](const Binary& bin) {
        std::string on_error;
        bool is_valid = check_layout(bin, &on_error);
        return std::pair<bool, std::string>{is_valid, on_error};
      },
      "Check the layout of the given Mach-O binary. It checks if it can be "
      "signed "
      "according to ``cctools-921/libstuff/checkout.c``",
      "file"_a);
}

}  // namespace MachO
}  // namespace LIEF
