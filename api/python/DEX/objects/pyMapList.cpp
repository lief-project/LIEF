/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "LIEF/DEX/hash.hpp"

#include "pyDEX.hpp"
#include "pyIterators.hpp"

namespace LIEF {
namespace DEX {

template<class T>
using getter_t = T (MapList::*)(void) const;

template<class T>
using no_const_getter_t = T (MapList::*)(void);

template<class T>
using setter_t = void (MapList::*)(T);


template<>
void create<MapList>(py::module& m) {

  init_ref_iterator<MapList::it_items_t>(m, "lief.DEX.MapList.it_items_t");

  py::class_<MapList, LIEF::Object>(m, "MapList", "DEX MapList representation")
    .def_property_readonly("items",
        static_cast<no_const_getter_t<MapList::it_items_t>>(&MapList::items),
        "Iterator over " RST_CLASS_REF(lief.DEX.MapItem) "")

    .def("has",
        &MapList::has,
        "Check if the given " RST_CLASS_REF(lief.DEX.MapItem.TYPES) " is present",
        "type"_a)

    .def("get",
        static_cast<MapItem&(MapList::*)(MapItem::TYPES)>(&MapList::get),
        "Return the " RST_CLASS_REF(lief.DEX.MapItem.TYPES) " from "
        "the given " RST_CLASS_REF(lief.DEX.MapItem.TYPES) "",
        "type"_a,
        py::return_value_policy::reference)

    .def("__getitem__",
        static_cast<MapItem&(MapList::*)(MapItem::TYPES)>(&MapList::get))

    .def("__eq__", &MapList::operator==)
    .def("__ne__", &MapList::operator!=)
    .def("__hash__",
        [] (const MapList& mlist) {
          return Hash::hash(mlist);
        })

    .def("__str__",
        [] (const MapList& mlist) {
          std::ostringstream stream;
          stream << mlist;
          return stream.str();
        });
}

}
}
