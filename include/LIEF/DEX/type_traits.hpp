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
#ifndef LIEF_DEX_TYPE_TRAITS_H_
#define LIEF_DEX_TYPE_TRAITS_H_

#include <vector>
#include <array>
#include <unordered_map>
#include <map>
#include "LIEF/iterators.hpp"

namespace LIEF {
namespace DEX {
class File;
class Class;
class Method;
class Type;
class Prototype;

using dex_version_t = uint32_t;
using magic_t     = std::array<uint8_t, 8>;
using signature_t = std::array<uint8_t, 20>;

using dex_files_t         = std::vector<File*>;
using it_dex_files        = ref_iterator<dex_files_t>;
using it_const_dex_files  = const_ref_iterator<const dex_files_t>;

using classes_t           = std::unordered_map<std::string, Class*>;
using classes_list_t      = std::vector<Class*>;
using it_classes          = ref_iterator<classes_list_t>;
using it_const_classes    = const_ref_iterator<const classes_list_t>;

using methods_t           = std::vector<Method*>;
using it_methods          = ref_iterator<methods_t>;
using it_const_methods    = const_ref_iterator<const methods_t>;

using strings_t           = std::vector<std::string*>;
using it_strings          = ref_iterator<strings_t>;
using it_const_strings    = const_ref_iterator<const strings_t>;

using types_t             = std::vector<Type*>;
using it_types            = ref_iterator<types_t>;
using it_const_types      = const_ref_iterator<const types_t>;

using prototypes_t        = std::vector<Prototype*>;
using it_protypes         = ref_iterator<prototypes_t>;
using it_const_protypes   = const_ref_iterator<const prototypes_t>;

// Method Index: {dex_pc: index, ...}
using dex2dex_method_info_t = std::map<uint32_t, uint32_t>;
using dex2dex_class_info_t  = std::map<Method*, dex2dex_method_info_t>;
using dex2dex_info_t        = std::unordered_map<Class*, dex2dex_class_info_t>;

}
}

#endif
