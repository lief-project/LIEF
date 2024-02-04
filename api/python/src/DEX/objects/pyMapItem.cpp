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
#include "LIEF/DEX/MapItem.hpp"
#include "LIEF/DEX/EnumToString.hpp"

#include "DEX/pyDEX.hpp"
#include "enums_wrapper.hpp"

#include <sstream>

#define PY_ENUM(x) to_string(x), x

namespace LIEF::DEX::py {

template<>
void create<MapItem>(nb::module_& m) {

  nb::class_<MapItem, LIEF::Object> mapitem(m, "MapItem",
      "DEX MapItem representation"_doc);

  enum_<MapItem::TYPES>(mapitem, "TYPES")
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
    .def_prop_ro("type",
        nb::overload_cast<>(&MapItem::type, nb::const_),
        "" RST_CLASS_REF(lief.DEX.MapItem.TYPES) " of the item"_doc)

    .def_prop_ro("offset",
        nb::overload_cast<>(&MapItem::offset, nb::const_),
        "Offset from the start of the file to the items in question"_doc)

    .def_prop_ro("size",
        nb::overload_cast<>(&MapItem::size, nb::const_),
        "count of the number of items to be found at the indicated offset"_doc)

    LIEF_DEFAULT_STR(MapItem);
}

}
