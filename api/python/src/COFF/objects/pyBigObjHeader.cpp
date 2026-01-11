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
#include "LIEF/COFF/BigObjHeader.hpp"

#include "nanobind/extra/stl/lief_span.h"

namespace LIEF::COFF::py {

template<>
void create<BigObjHeader>(nb::module_& m) {
  nb::class_<BigObjHeader, Header> hdr(m, "BigObjHeader",
    R"doc(
    This class represents the header for a COFF object compiled
    with ``/bigobj`` support (i.e. the number of sections can exceed 65536).

    The raw definition of the bigobj header is located in ``winnt.h`` and named
    ``ANON_OBJECT_HEADER_BIGOBJ``
    )doc"_doc);

  hdr
    .def_prop_rw("version",
      nb::overload_cast<>(&BigObjHeader::version, nb::const_),
      nb::overload_cast<uint16_t>(&BigObjHeader::version),
      "The version of this header which must be >= 2"_doc
    )

    .def_prop_ro("uuid",
      nb::overload_cast<>(&BigObjHeader::uuid, nb::const_),
      R"doc(
      Originally named ``ClassID``, this uuid should match:
      ``{D1BAA1C7-BAEE-4ba9-AF20-FAF66AA4DCB8}``.
      )doc"_doc
    )

    .def_prop_rw("sizeof_data",
      nb::overload_cast<>(&BigObjHeader::sizeof_data, nb::const_),
      nb::overload_cast<uint32_t>(&BigObjHeader::sizeof_data),
      "Size of data that follows the header"_doc
    )

    .def_prop_rw("flags",
      nb::overload_cast<>(&BigObjHeader::flags, nb::const_),
      nb::overload_cast<uint32_t>(&BigObjHeader::flags),
      "1 means that it contains metadata"_doc
    )

    .def_prop_rw("metadata_size",
      nb::overload_cast<>(&BigObjHeader::metadata_size, nb::const_),
      nb::overload_cast<uint32_t>(&BigObjHeader::metadata_size),
      "Size of CLR metadata"_doc
    )

    .def_prop_rw("metadata_offset",
      nb::overload_cast<>(&BigObjHeader::metadata_offset, nb::const_),
      nb::overload_cast<uint32_t>(&BigObjHeader::metadata_offset),
      "Offset of CLR metadata"_doc
    )
  ;
}

}
