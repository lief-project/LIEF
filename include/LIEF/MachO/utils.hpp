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
#ifndef LIEF_MACHO_UTILS_H_
#define LIEF_MACHO_UTILS_H_

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

#include <string>
#include <vector>

namespace LIEF {
namespace MachO {
LIEF_API bool is_macho(const std::string& file);

LIEF_API bool is_macho(const std::vector<uint8_t>& raw);

LIEF_API bool is_fat(const std::string& file);
LIEF_API bool is_64(const std::string& file);
LIEF_API uint64_t decode_uleb128(const std::string& file);
}
}


#endif
