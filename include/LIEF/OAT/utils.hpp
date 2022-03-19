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
#ifndef LIEF_OAT_UTILS_H_
#define LIEF_OAT_UTILS_H_

#include <string>
#include <vector>

#include "LIEF/OAT/type_traits.hpp"
#include "LIEF/platforms/android.hpp"
#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace ELF {
class Binary;
}
namespace OAT {

//! @brief Check if the given LIEF::ELF::Binary is an OAT one.
LIEF_API bool is_oat(const LIEF::ELF::Binary& elf_binary);

//! @brief Check if the given file is an OAT one.
LIEF_API bool is_oat(const std::string& file);

//! @brief Check if the given raw data is an OAT one.
LIEF_API bool is_oat(const std::vector<uint8_t>& raw);

//! @brief Return the OAT version of the given file
LIEF_API oat_version_t version(const std::string& file);

//! @brief Return the OAT version of the raw data
LIEF_API oat_version_t version(const std::vector<uint8_t>& raw);

//! @brief Return the OAT version of the given LIEF::ELF::Binary
LIEF_API oat_version_t version(const LIEF::ELF::Binary& elf_binary);

//! @brief Return the ANDROID_VERSIONS associated with the given OAT version
LIEF_API LIEF::Android::ANDROID_VERSIONS android_version(oat_version_t version);

}  // namespace OAT
}  // namespace LIEF

#endif
