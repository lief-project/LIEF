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
#ifndef LIEf_TYPE_TRAITS_H_
#define LIEf_TYPE_TRAITS_H_
#include <vector>
#include "LIEF/iterators.hpp"
namespace LIEF {
class Symbol;
class Section;
class Relocation;

using sections_t        = std::vector<Section*>;
using it_sections       = ref_iterator<sections_t>;
using it_const_sections = const_ref_iterator<sections_t>;

using symbols_t         = std::vector<Symbol*>;
using it_symbols        = ref_iterator<symbols_t>;
using it_const_symbols  = const_ref_iterator<symbols_t>;

using relocations_t        = std::vector<Relocation*>;          ///< Container used to transfert abstract relocations from binary formats
using it_relocations       = ref_iterator<relocations_t>;       ///< Iterator over Abstract LIEF::Relocation (read only)
using it_const_relocations = const_ref_iterator<relocations_t>; ///< Iterator over Abstract LIEF::Relocation (read/write)

}
#endif
