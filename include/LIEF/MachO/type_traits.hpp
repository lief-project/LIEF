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
#ifndef LIEF_MACHO_TYPE_TRAITS_H_
#define LIEF_MACHO_TYPE_TRAITS_H_
#include <vector>
#include <set>
#include "LIEF/iterators.hpp"
#include "LIEF/Abstract/Relocation.hpp"

namespace LIEF {
namespace MachO {
class LoadCommand;
class Symbol;
class SegmentCommand;
class DylibCommand;
class Section;
class Relocation;

class BindingInfo;
class ExportInfo;

template<class T>
struct KeyCmp {
  bool operator() (const T* lhs, const T* rhs) const { return *lhs < *rhs; };
};


using binaries_t                = std::vector<Binary*>;
using it_binaries               = ref_iterator<binaries_t&>;
using it_const_binaries         = const_ref_iterator<const binaries_t&>;


using buffer_t                  = std::vector<uint8_t>; ///< Container used to store raw data

using commands_t                = std::vector<LoadCommand*>;
using it_commands               = ref_iterator<commands_t>;
using it_const_commands         = const_ref_iterator<commands_t>;

using symbols_t                 = std::vector<Symbol*>;
using it_symbols                = ref_iterator<symbols_t&>;
using it_const_symbols          = const_ref_iterator<const symbols_t&>;

using it_exported_symbols       = filter_iterator<symbols_t>;
using it_const_exported_symbols = const_filter_iterator<symbols_t>;

using it_imported_symbols       = filter_iterator<symbols_t>;
using it_const_imported_symbols = const_filter_iterator<symbols_t>;

using libraries_t               = std::vector<DylibCommand*>;
using it_libraries              = ref_iterator<libraries_t>;
using it_const_libraries        = const_ref_iterator<libraries_t>;

using segments_t                = std::vector<SegmentCommand*>;
using it_segments               = ref_iterator<segments_t>;
using it_const_segments         = const_ref_iterator<segments_t>;

using sections_t                = std::vector<Section*>;
using it_sections               = ref_iterator<sections_t>;
using it_const_sections         = const_ref_iterator<sections_t>;

using relocations_t             = std::set<Relocation*, KeyCmp<Relocation>>;  ///< Container used to store relocations
using it_relocations            = ref_iterator<relocations_t&>;               ///< Iterator's type for relocations
using it_const_relocations      = const_ref_iterator<const relocations_t&>;   ///< Iterator's type for relocations (const)

using binding_info_t            = std::vector<BindingInfo*>;          ///< Container used to store BindinfInfo
using it_binding_info           = ref_iterator<binding_info_t>;       ///< Iterator's type for binding_info_t
using it_const_binding_info     = const_ref_iterator<binding_info_t>; ///< Iterator's type for binding_info_t (const)

using export_info_t             = std::vector<ExportInfo*>;           ///< Container used to store ExportInfo
using it_export_info            = ref_iterator<export_info_t>;        ///< Iterator's type for export_info_t
using it_const_export_info      = const_ref_iterator<export_info_t>;  ///< Iterator's type for export_info_t (const)


}
}

#endif
