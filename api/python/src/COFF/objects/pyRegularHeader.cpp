/* Copyright 2025 - 2026 R. Thomas
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
#include "COFF/pyCOFF.hpp"
#include "LIEF/COFF/RegularHeader.hpp"

namespace LIEF::COFF::py {

template<>
void create<RegularHeader>(nb::module_& m) {
  nb::class_<RegularHeader, Header>(m, "RegularHeader",
    R"doc(
    This class represents the COFF header for non-bigobj
    )doc"_doc)

    .def_prop_rw("sizeof_optionalheader",
      nb::overload_cast<>(&RegularHeader::sizeof_optionalheader, nb::const_),
      nb::overload_cast<uint16_t>(&RegularHeader::sizeof_optionalheader),
      "The size of the optional header that follows this header (should be 0)"_doc
    )

    .def_prop_rw("characteristics",
      nb::overload_cast<>(&RegularHeader::characteristics, nb::const_),
      nb::overload_cast<uint16_t>(&RegularHeader::characteristics),
      "Characteristics"_doc
    )
  ;

}

}
