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
#include "LIEF/PE/LoadConfigurations/CHPEMetadata/Metadata.hpp"
#include "PE/pyPE.hpp"

#include <string>
#include <sstream>

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::PE {
class CHPEMetadataARM64;
class CHPEMetadataX86;
}

namespace LIEF::PE::py {

template<>
void create<CHPEMetadata>(nb::module_& m) {
  nb::class_<CHPEMetadata> meta(m, "CHPEMetadata",
    R"delim(
    Base class for any Compiled Hybrid Portable Executable (CHPE) metadata.

    This class is inherited by architecture-specific implementation.
    )delim"_doc);

  nb::enum_<CHPEMetadata::KIND>(meta, "KIND",
    "Discriminator for the subclasses"_doc
  )
    .value("UNKNOWN", CHPEMetadata::KIND::UNKNOWN)
    .value("ARM64", CHPEMetadata::KIND::ARM64)
    .value("X86", CHPEMetadata::KIND::X86);

  meta
    .def_prop_ro("version", &CHPEMetadata::version,
      "Version of the structure"_doc
    )
    .def_prop_ro("kind", &CHPEMetadata::kind,
      "Determine the type of the concrete implementation"
    )
    LIEF_CLONABLE(CHPEMetadata)
    LIEF_DEFAULT_STR(CHPEMetadata);

  create<CHPEMetadataARM64>(m);
  create<CHPEMetadataX86>(m);
}
}
