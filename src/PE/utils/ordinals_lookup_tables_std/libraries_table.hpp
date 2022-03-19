/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#ifndef LIEF_PE_UTILS_LIBRARY_TABLE_STD_H_
#define LIEF_PE_UTILS_LIBRARY_TABLE_STD_H_

#include <unordered_map>

#include "oleauth32_dll_lookup.hpp"
#include "ws2_32_dll_lookup.hpp"

namespace LIEF {
namespace PE {
namespace imphashstd {

static const std::unordered_map<std::string, const char* (*)(uint32_t)>
    ordinals_library_tables = {
        {"ws2_32.dll", &ws2_32_dll_lookup},
        {"wsock32.dll", &ws2_32_dll_lookup},
        {"oleaut32.dll", &oleaut32_dll_lookup},
};
}
}  // namespace PE
}  // namespace LIEF

#endif
