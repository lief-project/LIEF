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
#ifndef LIEF_PE_UTILS_H_
#define LIEF_PE_UTILS_H_

#include <list>
#include <string>
#include <locale>
#include <memory>

#include "LIEF/visibility.h"

#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/Import.hpp"

namespace LIEF {
namespace PE {

//! @brief check if the `file` is a PE file
LIEF_API bool is_pe(const std::string& file);

//! @brief check if the raw data is a PE file
LIEF_API bool is_pe(const std::vector<uint8_t>& raw);

//! @brief if the input `file` is a PE one, return `PE32` or `PE32+`
LIEF_API PE_TYPE get_type(const std::string& file);

//! @brief Return `PE32` or `PE32+`
LIEF_API PE_TYPE get_type(const std::vector<uint8_t>& raw);

//! @brief Compute the hash of imported functions
//!
//! Properties of the hash generated:
//!   * Order agnostic
//!   * Casse agnostic
//!   * Ordinal (**in some extent**) agnostic
//!
//! @see https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html
LIEF_API std::string get_imphash(const Binary& binary);

//! @brief Take a PE::Import as entry and try to resolve imports
//! by ordinal.
//!
//! The ``strict`` boolean parameter enables to throw an LIEF::not_found exception
//! if the ordinal can't be resolved. Otherwise it skips the entry.
//!
//! @param[in]  import Import to resolve
//! @param[in]  strict If set to ``true``, throw an exception if the import can't be resolved
//! @param[out] Import The import resolved: PE::ImportEntry::name is set
LIEF_API Import resolve_ordinals(const Import& import, bool strict=false);
}
}
#endif
