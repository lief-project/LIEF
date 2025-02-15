/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include "LIEF/PE/debug/PDBChecksum.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/extra/memoryview.hpp>
#include "nanobind/extra/stl/lief_span.h"
#include "nanobind/utils.hpp"

namespace LIEF::PE::py {

template<>
void create<PDBChecksum>(nb::module_& m) {
  using HASH_ALGO = PDBChecksum::HASH_ALGO;
  nb::class_<PDBChecksum, Debug> entry(m, "PDBChecksum",
    R"doc(
    This class represents the PDB Checksum debug entry which is essentially
    an array of bytes representing the checksum of the PDB content.
    )doc"_doc);

  nb::enum_<HASH_ALGO>(entry, "HASH_ALGO")
    .value("UNKNOWN", HASH_ALGO::UNKNOWN)
    .value("SHA256", HASH_ALGO::SHA256);

  entry
    .def(nb::init<HASH_ALGO, std::vector<uint8_t>>(), "algo"_a, "hash"_a)
    .def_prop_rw("hash",
      nb::overload_cast<>(&PDBChecksum::hash),
      nb::overload_cast<std::vector<uint8_t>>(&PDBChecksum::hash),
      "Hash of the PDB content"_doc
    )

    .def_prop_rw("algorithm",
      nb::overload_cast<>(&PDBChecksum::algorithm, nb::const_),
      nb::overload_cast<HASH_ALGO>(&PDBChecksum::algorithm),
      "Algorithm used for hashing the PDB content"_doc
    )
    LIEF_DEFAULT_STR(PDBChecksum);
}
}
