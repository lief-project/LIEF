/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#include "LIEF/MachO/type_traits.hpp"
#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

void init_iterators(py::module& m) {
  init_ref_iterator<LIEF::MachO::it_binaries>(m, "it_binaries");
  init_ref_iterator<LIEF::MachO::it_fileset_binaries>(m, "it_fileset_binaries");
  init_ref_iterator<LIEF::MachO::it_relocations>(m, "it_relocations");
  init_ref_iterator<LIEF::MachO::it_commands>(m, "it_commands");
  init_ref_iterator<LIEF::MachO::it_symbols>(m, "it_symbols");
  init_ref_iterator<LIEF::filter_iterator<LIEF::MachO::symbols_t>>(m, "it_filter_symbols");
  init_ref_iterator<LIEF::MachO::it_libraries>(m, "it_libraries");
  init_ref_iterator<LIEF::MachO::it_segments>(m, "it_segments");
  init_ref_iterator<LIEF::MachO::it_sections>(m, "it_sections");
  init_ref_iterator<LIEF::MachO::it_binding_info>(m, "it_binding_info");
  init_ref_iterator<LIEF::MachO::it_export_info>(m, "it_export_info");
}

}
}
