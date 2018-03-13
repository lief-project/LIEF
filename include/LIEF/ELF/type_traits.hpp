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
#ifndef LIEF_ELF_TYPE_TRAITS_H_
#define LIEF_ELF_TYPE_TRAITS_H_
#include <vector>
#include <set>
#include "LIEF/iterators.hpp"

#include "LIEF/ELF/Structures.hpp"

namespace LIEF {
namespace ELF {
class Section;
class Segment;
class DynamicEntry;
class Symbol;
class Relocation;
class Section;
class SymbolVersion;
class SymbolVersionRequirement;
class SymbolVersionDefinition;
class SymbolVersionAux;
class SymbolVersionAuxRequirement;
class Note;

using sections_t                               = std::vector<Section*>;
using it_sections                              = ref_iterator<sections_t&>;
using it_const_sections                        = const_ref_iterator<const sections_t&>;

using segments_t                               = std::vector<Segment*>;
using it_segments                              = ref_iterator<segments_t&>;
using it_const_segments                        = const_ref_iterator<const segments_t&>;

using dynamic_entries_t                        = std::vector<DynamicEntry*>;
using it_dynamic_entries                       = ref_iterator<dynamic_entries_t&>;
using it_const_dynamic_entries                 = const_ref_iterator<const dynamic_entries_t&>;

using symbols_t                                = std::vector<Symbol*>;
using it_symbols                               = ref_iterator<symbols_t>;
using it_const_symbols                         = const_ref_iterator<symbols_t>;

using relocations_t                            = std::vector<Relocation*>;

using it_pltgot_relocations                    = filter_iterator<relocations_t>;
using it_const_pltgot_relocations              = const_filter_iterator<const relocations_t>;

using it_dynamic_relocations                   = filter_iterator<relocations_t>;
using it_const_dynamic_relocations             = const_filter_iterator<const relocations_t>;

using it_object_relocations                    = filter_iterator<relocations_t>;
using it_const_object_relocations              = const_filter_iterator<const relocations_t>;

using it_relocations                           = ref_iterator<relocations_t&>;
using it_const_relocations                     = const_ref_iterator<const relocations_t&>;

using symbols_version_t                        = std::vector<SymbolVersion*>;
using it_symbols_version                       = ref_iterator<symbols_version_t&>;
using it_const_symbols_version                 = const_ref_iterator<const symbols_version_t&>;

using symbols_version_requirement_t            = std::vector<SymbolVersionRequirement*>;
using it_symbols_version_requirement           = ref_iterator<symbols_version_requirement_t&>;
using it_const_symbols_version_requirement     = const_ref_iterator<const symbols_version_requirement_t&>;

using symbols_version_definition_t             = std::vector<SymbolVersionDefinition*>;
using it_symbols_version_definition            = ref_iterator<symbols_version_definition_t&>;
using it_const_symbols_version_definition      = const_ref_iterator<const symbols_version_definition_t&>;

using it_exported_symbols                      = filter_iterator<symbols_t>;
using it_const_exported_symbols                = const_filter_iterator<symbols_t>;

using it_imported_symbols                      = filter_iterator<symbols_t>;
using it_const_imported_symbols                = const_filter_iterator<symbols_t>;

using symbols_version_aux_t                    = std::vector<SymbolVersionAux*>;
using it_symbols_version_aux                   = ref_iterator<symbols_version_aux_t&>;
using it_const_symbols_version_aux             = const_ref_iterator<const symbols_version_aux_t&>;

using symbols_version_aux_requirement_t        = std::vector<SymbolVersionAuxRequirement*>;
using it_symbols_version_aux_requirement       = ref_iterator<symbols_version_aux_requirement_t&>;
using it_const_symbols_version_aux_requirement = const_ref_iterator<const symbols_version_aux_requirement_t&>;

using notes_t                                  = std::vector<Note*>;
using it_notes                                 = ref_iterator<notes_t&>;
using it_const_notes                           = const_ref_iterator<const notes_t&>;

template<class T>
using flags_list_t = std::set<T>;

using arm_flags_list_t     = flags_list_t<ARM_EFLAGS>;
using mips_flags_list_t    = flags_list_t<MIPS_EFLAGS>;
using hexagon_flags_list_t = flags_list_t<HEXAGON_EFLAGS>;
using ppc64_flags_list_t   = flags_list_t<PPC64_EFLAGS>;

}
}

#endif
