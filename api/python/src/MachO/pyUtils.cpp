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
#include "MachO/pyMachO.hpp"
#include <nanobind/stl/pair.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "LIEF/MachO/utils.hpp"
#include "LIEF/MachO/FatBinary.hpp"
#include "LIEF/MachO/Binary.hpp"

namespace LIEF::MachO::py {

void init_utils(nb::module_& m) {
  lief_mod->def("is_macho",
      nb::overload_cast<const std::string&>(&is_macho),
      "Check if the given file is a ``MachO`` (from filename)"_doc,
      "filename"_a);

  lief_mod->def("is_macho",
      nb::overload_cast<const std::vector<uint8_t>&>(&is_macho),
      "Check if the given raw data is a ``MachO``"_doc,
      "raw"_a);

  m.def("is_fat", &is_fat,
      "Check if the given Mach-O is fat"_doc,
      "file"_a);

  m.def("is_64", &is_64,
      "Check if the given Mach-O is 64-bits"_doc,
      "file"_a);

  m.def("check_layout",
      [] (const Binary& bin) {
        std::string on_error;
        const bool is_valid = check_layout(bin, &on_error);
        return std::pair<bool, std::string>{is_valid, on_error};
      },
      "Check the layout of the given Mach-O binary. It checks if it can be signed "
      "according to ``cctools-921/libstuff/checkout.c``"_doc,
      "file"_a);

  m.def("check_layout",
      [] (const FatBinary& bin) {
        std::string on_error;
        const bool is_valid = check_layout(bin, &on_error);
        return std::pair<bool, std::string>{is_valid, on_error};
      },
      R"delim(
      Check the layout of the given FAT Mach-O by checking individually the layout
      of the binaries embedded in the FAT.
      )delim"_doc,
      "file"_a);
}
}
