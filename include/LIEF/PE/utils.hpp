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
#include <vector>
#include <string>

#include "LIEF/PE/enums.hpp"
#include "LIEF/visibility.h"


namespace LIEF {
namespace PE {
class Binary;
class Import;

//! check if the `file` is a PE file
LIEF_API bool is_pe(const std::string& file);

//! check if the raw data is a PE file
LIEF_API bool is_pe(const std::vector<uint8_t>& raw);

//! if the input `file` is a PE one, return `PE32` or `PE32+`
LIEF_API PE_TYPE get_type(const std::string& file);

//! Return `PE32` or `PE32+`
LIEF_API PE_TYPE get_type(const std::vector<uint8_t>& raw);

//! Compute the hash of imported functions
//!
//! Properties of the hash generated:
//!   * Order agnostic
//!   * Casse agnostic
//!   * Ordinal (**in some extent**) agnostic
//!
//! @warning The algorithm used to compute the *imphash* value has some variations compared to Yara, pefile, VT implementation
//!
//! @see https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html
LIEF_API std::string get_imphash(const Binary& binary);

//! Take a PE::Import as entry and try to resolve imports
//! by ordinal.
//!
//! The ``strict`` boolean parameter enables to throw an LIEF::not_found exception
//! if the ordinal can't be resolved. Otherwise it skips the entry.
//!
//! @param[in]  import Import to resolve
//! @param[in]  strict If set to ``true``, throw an exception if the import can't be resolved
//!
//! @return The PE::import resolved with PE::ImportEntry::name set
LIEF_API Import resolve_ordinals(const Import& import, bool strict=false);

LIEF_API ALGORITHMS algo_from_oid(const std::string& oid);
}
}
#endif
