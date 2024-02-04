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
#include "PE/pyPE.hpp"

#include "LIEF/PE/resources/ResourceDialogItem.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

#include "nanobind/extra/stl/u16string.h"

namespace LIEF::PE::py {

template<>
void create<ResourceDialogItem>(nb::module_& m) {
  nb::class_<ResourceDialogItem, LIEF::Object>(m, "ResourceDialogItem",
      R"delim(
      This class represents an item in the :class:`lief.PE.ResourceDialog`
      )delim"_doc)

    .def_prop_ro("is_extended",
        &ResourceDialogItem::is_extended,
        "``True`` if the control is an extended one"_doc)

    .def_prop_ro("help_id",
        nb::overload_cast<>(&ResourceDialogItem::help_id, nb::const_),
        "The help context identifier for the control"_doc)

    .def_prop_ro("extended_style",
        nb::overload_cast<>(&ResourceDialogItem::extended_style, nb::const_),
        "The extended styles for the window"_doc)

    .def_prop_ro("style",
        nb::overload_cast<>(&ResourceDialogItem::style, nb::const_),
        "The style of the control. This member can be a combination of "
        "" RST_CLASS_REF(lief.PE.WINDOW_STYLES) "  values "
        "and one or more of the control style values."_doc)

    .def_prop_ro("x",
        nb::overload_cast<>(&ResourceDialogItem::x, nb::const_),
        "The x-coordinate, in dialog box units, of the upper-left corner of the control"_doc)

    .def_prop_ro("y",
        nb::overload_cast<>(&ResourceDialogItem::y, nb::const_),
        "The y-coordinate, in dialog box units, of the upper-left corner of the control"_doc)

    .def_prop_ro("cx",
        nb::overload_cast<>(&ResourceDialogItem::cx, nb::const_),
        "The width, in dialog box units, of the control"_doc)

    .def_prop_ro("cy",
        nb::overload_cast<>(&ResourceDialogItem::cy, nb::const_),
        "The height, in dialog box units, of the control"_doc)

    .def_prop_ro("id",
        nb::overload_cast<>(&ResourceDialogItem::id, nb::const_),
        "The control identifier"_doc)

    .def_prop_ro("title",
        nb::overload_cast<>(&ResourceDialogItem::title, nb::const_),
        "Initial text of the control"_doc)

    LIEF_DEFAULT_STR(ResourceDialogItem);
}
}

