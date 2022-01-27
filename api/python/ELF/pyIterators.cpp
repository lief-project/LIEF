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
#include "LIEF/ELF/type_traits.hpp"
#include "pyELF.hpp"

namespace LIEF {
namespace ELF {

void init_iterators(py::module& m) {
  init_ref_iterator<LIEF::ELF::it_sections>(m, "it_sections");
  init_ref_iterator<LIEF::ELF::it_segments>(m, "it_segments");
  init_ref_iterator<LIEF::ELF::it_dynamic_entries>(m, "it_dynamic_entries");
  init_ref_iterator<LIEF::ELF::it_symbols>(m, "it_symbols");
  init_ref_iterator<LIEF::filter_iterator<LIEF::ELF::relocations_t>>(m, "it_fileter_relocations");
  init_ref_iterator<LIEF::ELF::it_symbols_version>(m, "it_symbols_version");
  init_ref_iterator<LIEF::ELF::it_relocations>(m, "it_relocations");
  init_ref_iterator<LIEF::ELF::it_symbols_version_requirement>(m, "it_symbols_version_requirement");
  init_ref_iterator<LIEF::ELF::it_symbols_version_definition>(m, "it_symbols_version_definition");
  init_ref_iterator<LIEF::filter_iterator<LIEF::ELF::symbols_t>>(m, "it_filter_symbols");
  init_ref_iterator<LIEF::ELF::it_symbols_version_aux>(m, "it_symbols_version_aux");
  init_ref_iterator<LIEF::ELF::it_symbols_version_aux_requirement>(m, "it_symbols_version_aux_requirement");
  init_ref_iterator<LIEF::ELF::it_notes>(m, "it_notes");
}

}
}
