/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#ifndef LIEF_PE_TYPE_TRAITS_H_
#define LIEF_PE_TYPE_TRAITS_H_
#include <vector>
#include "LIEF/iterators.hpp"
#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {
class Section;
class DataDirectory;
class Relocation;
class Symbol;
class ExportEntry;
class RichEntry;
class RelocationEntry;

class Import;
class ImportEntry;

class ResourceNode;
class ResourceIcon;
class ResourceDialogItem;

using sections_t                = std::vector<Section*>;
using it_sections               = ref_iterator<sections_t>;       ///< Iterator type for LIEF::PE::Section
using it_const_sections         = const_ref_iterator<sections_t>; ///< Iterator type for LIEF::PE::Section (without modification)

using data_directories_t        = std::vector<DataDirectory*>;
using it_data_directories       = ref_iterator<data_directories_t>;
using it_const_data_directories = const_ref_iterator<data_directories_t>;

using relocations_t             = std::vector<Relocation*>;
using it_relocations            = ref_iterator<relocations_t&>;
using it_const_relocations      = const_ref_iterator<const relocations_t&>;


using relocation_entries_t        = std::vector<RelocationEntry*>;
using it_relocation_entries       = ref_iterator<relocation_entries_t&>;
using it_const_relocation_entries = const_ref_iterator<const relocation_entries_t&>;

using imports_t                 = std::vector<Import>;
using it_imports                = ref_iterator<imports_t&>;
using it_const_imports          = const_ref_iterator<const imports_t&>;

using import_entries_t          = std::vector<ImportEntry>;
using it_import_entries         = ref_iterator<import_entries_t&>;
using it_const_import_entries   = const_ref_iterator<const import_entries_t&>;

using export_entries_t          = std::vector<ExportEntry>;
using it_export_entries         = ref_iterator<export_entries_t&>;
using it_const_export_entries   = const_ref_iterator<const export_entries_t&>;

using symbols_t                 = std::vector<Symbol>;
using it_symbols                = ref_iterator<symbols_t&>;
using it_const_symbols          = const_ref_iterator<const symbols_t&>;

using strings_table_t           = std::vector<std::string>;
using it_strings_table          = ref_iterator<strings_table_t&>;
using it_const_strings_table    = const_ref_iterator<const strings_table_t&>;

using childs_t                  = std::vector<ResourceNode*>;
using it_childs                 = ref_iterator<childs_t&>;
using it_const_childs           = const_ref_iterator<const childs_t&>;

using dialog_items_t            = std::vector<ResourceDialogItem>;
using it_dialog_items           = ref_iterator<dialog_items_t&>;
using it_const_dialog_items     = const_ref_iterator<const dialog_items_t&>;

using rich_entries_t            = std::vector<RichEntry>;
using it_rich_entries           = ref_iterator<rich_entries_t&>;
using it_const_rich_entries     = const_ref_iterator<const rich_entries_t&>;


template<class T>
using flags_list_t = std::set<T>;

using guard_cf_flags_list_t = flags_list_t<GUARD_CF_FLAGS>;

}
}

#endif
