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
#include "LIEF/DEX/MapList.hpp"

#include "DEX/pyDEX.hpp"
#include "pyIterator.hpp"

#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::DEX::py {

template<>
void create<MapList>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<MapList, LIEF::Object> map_list(m, "MapList",
      "DEX MapList representation"_doc);

  init_ref_iterator<MapList::it_items_t>(map_list, "it_items_t");

  map_list
    .def_prop_ro("items", nb::overload_cast<>(&MapList::items),
        "Iterator over " RST_CLASS_REF(lief.DEX.MapItem) ""_doc)

    .def("has", &MapList::has,
        "Check if the given " RST_CLASS_REF(lief.DEX.MapItem.TYPES) " is present"_doc,
        "type"_a)

    .def("get", nb::overload_cast<MapItem::TYPES>(&MapList::get),
        R"delim(
        Return the :class:`~lief.DEX.MapItem` from the given
        :class:`~lief.DEX.MapItem.TYPES`
        )delim"_doc, "type"_a, nb::rv_policy::reference_internal)

    .def("__getitem__",
        nb::overload_cast<MapItem::TYPES>(&MapList::get))

    LIEF_DEFAULT_STR(MapList);

}
}
