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
#ifndef LIEF_MACHO_UTILS_H_
#define LIEF_MACHO_UTILS_H_

#include <string>
#include <vector>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace MachO {
class Binary;

//! Check if the given file is a Mach-O binary
LIEF_API bool is_macho(const std::string& file);

//! Check if the given raw data is a Mach-O binary
LIEF_API bool is_macho(const std::vector<uint8_t>& raw);

//! Check if the given file is a FAT Mach-O
LIEF_API bool is_fat(const std::string& file);

//! Check if the given Mach-O is 64-bits
LIEF_API bool is_64(const std::string& file);

//! Check the layout of the given Mach-O binary. It checks if it can be signed
//! according to cctools-921/libstuff/checkout.c
LIEF_API bool check_layout(const Binary& binary, std::string* error = nullptr);
}  // namespace MachO
}  // namespace LIEF

#endif
