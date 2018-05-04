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
#ifndef LIEF_DEX_UTILS_H_
#define LIEF_DEX_UTILS_H_

#include <string>
#include <vector>

#include "LIEF/DEX/type_traits.hpp"

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace DEX {

//! @brief Check if the given file is an DEX one.
LIEF_API bool is_dex(const std::string& file);

//! @brief Check if the given raw data is an DEX one.
LIEF_API bool is_dex(const std::vector<uint8_t>& raw);

//! @brief Return the DEX version of the given file
LIEF_API dex_version_t version(const std::string& file);

//! @brief Return the DEX version of the raw data
LIEF_API dex_version_t version(const std::vector<uint8_t>& raw);

}
}


#endif
