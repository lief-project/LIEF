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
#include "LIEF/PE/LoadConfigurations/VolatileMetadata.hpp"
#include "PE/pyPE.hpp"

#include <string>
#include <sstream>

#include "pyIterator.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/array.h>
#include <nanobind/stl/vector.h>

namespace LIEF::PE::py {

template<>
void create<VolatileMetadata>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<VolatileMetadata> meta(m, "VolatileMetadata",
    R"doc(
    This class represents volatile metadata which can be enabled at link time
    with ``/volatileMetadata``.

    This metadata aims to improve performances when running x64 code on ARM64.
    )doc"_doc
  );

  using range_t = VolatileMetadata::range_t;

  nb::class_<range_t>(meta, "range_t")
    .def_rw("start", &range_t::start)
    .def_rw("size", &range_t::size)
    .def_prop_ro("end", &range_t::end);

  init_ref_iterator<VolatileMetadata::it_info_ranges_t>(meta, "it_info_ranges_t");

  meta
    .def_prop_rw("size",
      nb::overload_cast<>(&VolatileMetadata::size, nb::const_),
      nb::overload_cast<uint32_t>(&VolatileMetadata::size),
      R"doc()doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("min_version",
      nb::overload_cast<>(&VolatileMetadata::min_version, nb::const_),
      nb::overload_cast<uint16_t>(&VolatileMetadata::min_version),
      R"doc()doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("max_version",
      nb::overload_cast<>(&VolatileMetadata::max_version, nb::const_),
      nb::overload_cast<uint16_t>(&VolatileMetadata::max_version),
      R"doc()doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("access_table_rva",
      nb::overload_cast<>(&VolatileMetadata::access_table_rva, nb::const_),
      nb::overload_cast<uint32_t>(&VolatileMetadata::access_table_rva),
      R"doc()doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_ro("access_table",
      nb::overload_cast<>(&VolatileMetadata::access_table, nb::const_),
      R"doc()doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_ro("access_table_size",
      nb::overload_cast<>(&VolatileMetadata::access_table_size, nb::const_),
      R"doc()doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("info_range_rva",
      nb::overload_cast<>(&VolatileMetadata::info_range_rva, nb::const_),
      nb::overload_cast<uint32_t>(&VolatileMetadata::info_range_rva),
      R"doc()doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_ro("info_ranges_size",
      nb::overload_cast<>(&VolatileMetadata::info_ranges_size, nb::const_),
      R"doc()doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_ro("info_ranges",
      nb::overload_cast<>(&VolatileMetadata::info_ranges),
      R"doc()doc"_doc,
      nb::rv_policy::reference_internal
    )
    LIEF_DEFAULT_STR(VolatileMetadata);

}
}
