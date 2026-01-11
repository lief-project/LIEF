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

#include <nanobind/stl/unique_ptr.h>

#include "LIEF/COFF/Header.hpp"
#include "enums_wrapper.hpp"

#include <sstream>

namespace LIEF::COFF {
class BigObjHeader;
class RegularHeader;
namespace py {

template<>
void create<Header>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Header> hdr(m, "Header",
    R"doc(
    Class that represents the COFF header. It is subclassed by
    :class:`~.RegularHeader` and :class:`~.BigObjHeader` for normal vs
    ``/bigobj`` files
    )doc"_doc);

  nb::enum_<Header::KIND>(hdr, "KIND")
    .value("UNKNOWN", Header::KIND::UNKNOWN)
    .value("REGULAR", Header::KIND::REGULAR)
    .value("BIGOBJ", Header::KIND::BIGOBJ);

  hdr
    .def_prop_ro("kind", &Header::kind,
      R"doc(
      The type of this header: whether it is regular or using the ``/bigobj``
      format
      )doc"_doc
    )

    .def_prop_rw("machine",
      nb::overload_cast<>(&Header::machine, nb::const_),
      nb::overload_cast<Header::MACHINE_TYPES>(&Header::machine),
      "The machine type targeted by this COFF"_doc
    )

    .def_prop_rw("nb_sections",
      nb::overload_cast<>(&Header::nb_sections, nb::const_),
      nb::overload_cast<uint32_t>(&Header::nb_sections),
      "The number of sections"_doc
    )

    .def_prop_rw("pointerto_symbol_table",
      nb::overload_cast<>(&Header::pointerto_symbol_table, nb::const_),
      nb::overload_cast<uint32_t>(&Header::pointerto_symbol_table),
      "Offset of the symbols table"_doc
    )

    .def_prop_rw("nb_symbols",
      nb::overload_cast<>(&Header::nb_symbols, nb::const_),
      nb::overload_cast<uint32_t>(&Header::nb_symbols),
      "Number of symbols (including auxiliary symbols)"_doc
    )

    .def_prop_rw("timedatestamp",
      nb::overload_cast<>(&Header::timedatestamp, nb::const_),
      nb::overload_cast<uint32_t>(&Header::timedatestamp),
      "Timestamp when the COFF has been generated"_doc
    )

  LIEF_DEFAULT_STR(Header)
  LIEF_CLONABLE(Header);

  create<RegularHeader>(m);
  create<BigObjHeader>(m);
}

}
}
