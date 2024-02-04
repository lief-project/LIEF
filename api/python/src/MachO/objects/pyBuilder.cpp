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
#include "pyErr.hpp"

#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/FatBinary.hpp"
#include "LIEF/MachO/Builder.hpp"

#include <nanobind/stl/string.h>

namespace LIEF::MachO::py {

template<>
void create<Builder>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Builder> builder(m, "Builder",
      R"delim(
      Class used to reconstruct a Mach-O binary from its object representation
      )delim"_doc);

  nb::class_<Builder::config_t>(builder, "config_t",
                                "Interface to tweak the " RST_CLASS_REF(lief.MachO.Builder) ""_doc)
    .def(nb::init<>())
    .def_rw("linkedit", &Builder::config_t::linkedit);

  builder
    .def_static("write",
                [] (Binary& bin, const std::string& out) {
                  auto target = nb::overload_cast<Binary&, const std::string&>(&Builder::write);
                  return error_or(target, bin, out);
                },
                R"delim(
                )delim",
                "binary"_a, "output"_a)
    .def_static("write",
                [] (Binary& bin, const std::string& out, Builder::config_t config) {
                  auto target = nb::overload_cast<Binary&, const std::string&, Builder::config_t>(&Builder::write);
                  return error_or(target, bin, out, config);
                },
                R"delim(
                )delim",
                "binary"_a, "output"_a, "config"_a)
    .def_static("write",
                [] (FatBinary& fat, const std::string& out) {
                  auto target = nb::overload_cast<FatBinary&, const std::string&>(&Builder::write);
                  return error_or(target, fat, out);
                },
                R"delim(
                )delim",
                "fat_binary"_a, "output"_a)
    .def_static("write",
                [] (FatBinary& fat, const std::string& out, Builder::config_t config) {
                  auto target = nb::overload_cast<FatBinary&, const std::string&, Builder::config_t>(&Builder::write);
                  return error_or(target, fat, out, config);
                },
                R"delim(
                )delim",
                "fat_binary"_a, "output"_a, "config"_a);
}
}
