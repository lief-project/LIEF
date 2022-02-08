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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/resources/ResourceDialogItem.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (ResourceDialogItem::*)(void) const;

template<class T>
using setter_t = void (ResourceDialogItem::*)(T);


template<>
void create<ResourceDialogItem>(py::module& m) {
  py::class_<ResourceDialogItem, LIEF::Object>(m, "ResourceDialogItem",
      R"delim(
      This class represents an item in the :class:`lief.PE.ResourceDialog`
      )delim")

    .def_property_readonly("is_extended",
        &ResourceDialogItem::is_extended,
        "``True`` if the control is an extended one")

    .def_property_readonly("help_id",
        static_cast<getter_t<uint32_t>>(&ResourceDialogItem::help_id),
        "The help context identifier for the control")

    .def_property_readonly("extended_style",
        static_cast<getter_t<uint32_t>>(&ResourceDialogItem::extended_style),
        "The extended styles for the window")

    .def_property_readonly("style",
        static_cast<getter_t<uint32_t>>(&ResourceDialogItem::style),
        "The style of the control. This member can be a combination of "
        "" RST_CLASS_REF(lief.PE.WINDOW_STYLES) "  values "
        "and one or more of the control style values.")

    .def_property_readonly("x",
        static_cast<getter_t<int16_t>>(&ResourceDialogItem::x),
        "The x-coordinate, in dialog box units, of the upper-left corner of the control")

    .def_property_readonly("y",
        static_cast<getter_t<int16_t>>(&ResourceDialogItem::y),
        "The y-coordinate, in dialog box units, of the upper-left corner of the control")

    .def_property_readonly("cx",
        static_cast<getter_t<int16_t>>(&ResourceDialogItem::cx),
        "The width, in dialog box units, of the control")

    .def_property_readonly("cy",
        static_cast<getter_t<int16_t>>(&ResourceDialogItem::cy),
        "The height, in dialog box units, of the control")

    .def_property_readonly("id",
        static_cast<getter_t<uint32_t>>(&ResourceDialogItem::id),
        "The control identifier")

    .def_property_readonly("title",
        static_cast<getter_t<const std::u16string&>>(&ResourceDialogItem::title),
        "Initial text of the control")

    .def("__eq__", &ResourceDialogItem::operator==)
    .def("__ne__", &ResourceDialogItem::operator!=)
    .def("__hash__",
        [] (const ResourceDialogItem& dialog) {
          return Hash::hash(dialog);
        })

    .def("__str__",
        [] (const ResourceDialogItem& dialog_item) {
          std::ostringstream stream;
          stream << dialog_item;
          std::string str = stream.str();
          return str;
        });
}

}
}

