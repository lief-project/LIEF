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
#include "LIEF/PE/type_traits.hpp"
#include "pyPE.hpp"

namespace LIEF {
namespace PE {

void init_iterators(py::module& m) {
  init_ref_iterator<LIEF::PE::it_sections>(m, "it_section");
  init_ref_iterator<LIEF::PE::it_data_directories>(m, "it_data_directories");
  init_ref_iterator<LIEF::PE::it_relocations>(m, "it_relocations");
  init_ref_iterator<LIEF::PE::it_relocation_entries>(m, "it_relocation_entries");
  init_ref_iterator<LIEF::PE::it_imports>(m, "it_imports");
  init_ref_iterator<LIEF::PE::it_import_entries>(m, "it_import_entries");
  init_ref_iterator<LIEF::PE::it_export_entries>(m, "it_export_entries");
  init_ref_iterator<LIEF::PE::it_pogo_entries>(m, "it_pogo_entries");
  init_ref_iterator<LIEF::PE::it_symbols>(m, "it_symbols");
  init_ref_iterator<LIEF::PE::it_childs>(m, "it_childs");
  init_ref_iterator<LIEF::PE::it_rich_entries>(m, "it_rich_entries");
  init_ref_iterator<LIEF::PE::it_const_dialog_items>(m, "it_const_dialog_items");
  init_ref_iterator<LIEF::PE::it_const_crt>(m, "it_const_crt");
  init_ref_iterator<LIEF::PE::it_const_signatures>(m, "it_const_signatures");
  init_ref_iterator<LIEF::PE::it_const_signers_t>(m, "it_const_signers_t");
  init_ref_iterator<LIEF::PE::it_const_attributes_t>(m, "it_const_attributes_t");
}

}
}
