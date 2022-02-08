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
#include "LIEF/DEX/MapItem.hpp"
#include "LIEF/DEX/hash.hpp"
#include "LIEF/DEX/EnumToString.hpp"

#include "pyDEX.hpp"

namespace LIEF {
namespace DEX {

#define PY_ENUM(x) to_string(x), x

template<class T>
using getter_t = T (MapItem::*)(void) const;

template<class T>
using no_const_getter_t = T (MapItem::*)(void);

template<class T>
using setter_t = void (MapItem::*)(T);


template<>
void create<MapItem>(py::module& m) {

  py::class_<MapItem, LIEF::Object> mapitem(m, "MapItem", "DEX MapItem representation");

  py::enum_<MapItem::TYPES>(mapitem, "TYPES")
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::HEADER))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::STRING_ID))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::TYPE_ID))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::PROTO_ID))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::FIELD_ID))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::METHOD_ID))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::CLASS_DEF))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::CALL_SITE_ID))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::METHOD_HANDLE))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::MAP_LIST))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::TYPE_LIST))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::ANNOTATION_SET_REF_LIST))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::ANNOTATION_SET))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::CLASS_DATA))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::CODE))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::STRING_DATA))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::DEBUG_INFO))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::ANNOTATION))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::ENCODED_ARRAY))
    .value(PY_ENUM(LIEF::DEX::MapItem::TYPES::ANNOTATIONS_DIRECTORY));

    mapitem
    .def_property_readonly("type",
        static_cast<getter_t<MapItem::TYPES>>(&MapItem::type),
        "" RST_CLASS_REF(lief.DEX.MapItem.TYPES) " of the item")

    .def_property_readonly("offset",
        static_cast<getter_t<uint32_t>>(&MapItem::offset),
        "Offset from the start of the file to the items in question")

    .def_property_readonly("size",
        static_cast<getter_t<uint32_t>>(&MapItem::size),
        "count of the number of items to be found at the indicated offset")

    .def("__eq__", &MapItem::operator==)
    .def("__ne__", &MapItem::operator!=)
    .def("__hash__",
        [] (const MapItem& mlist) {
          return Hash::hash(mlist);
        })

    .def("__str__",
        [] (const MapItem& mlist) {
          std::ostringstream stream;
          stream << mlist;
          return stream.str();
        });
}

}
}
