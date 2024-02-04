
/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include "PE/pyPE.hpp"

#include "LIEF/PE/signature/SpcIndirectData.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/extra/memoryview.hpp>

namespace LIEF::PE::py {

template<>
void create<SpcIndirectData>(nb::module_& m) {
  nb::class_<SpcIndirectData, ContentInfo::Content>(m, "SpcIndirectData")
    .def_prop_ro("digest_algorithm", &SpcIndirectData::digest_algorithm,
                 R"delim(
                 Digest used to hash the file. This should match
                 :attr:`~lief.PE.SignerInfo.digest_algorithm`
                 )delim"_doc)

    .def_prop_ro("digest", [] (const SpcIndirectData& sid) {
                   const span<const uint8_t> digest = sid.digest();
                   return nb::memoryview::from_memory(digest.data(), digest.size());
                 })
    .def_prop_ro("file", &SpcIndirectData::file)
    LIEF_DEFAULT_STR(SpcIndirectData);
}

}

