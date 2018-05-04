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
#ifndef LIEF_OAT_TYPE_TRAITS_H_
#define LIEF_OAT_TYPE_TRAITS_H_

#include <vector>
#include <unordered_map>
#include <map>
#include "LIEF/DEX.hpp"

#include "LIEF/iterators.hpp"


namespace LIEF {
namespace OAT {
class DexFile;
class Class;
class Method;

using oat_version_t = uint32_t;

using dex_files_t        = std::vector<DexFile*>;
using it_dex_files       = ref_iterator<dex_files_t>;
using it_const_dex_files = const_ref_iterator<const dex_files_t>;

using classes_t         = std::unordered_map<std::string, Class*>;
using classes_list_t    = std::vector<Class*>;
using it_classes        = ref_iterator<classes_list_t>;
using it_const_classes  = const_ref_iterator<const classes_list_t>;

using methods_t         = std::vector<Method*>;
using it_methods        = ref_iterator<methods_t>;
using it_const_methods  = const_ref_iterator<const methods_t>;

using dex2dex_info_t    = std::map<DEX::File*, DEX::dex2dex_info_t>;


}
}

#endif
