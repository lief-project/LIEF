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
#include "PE/pyPE.hpp"
#include "pyIterator.hpp"

#include "LIEF/PE/resources/ResourceDialogExtended.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include "nanobind/extra/stl/u16string.h"

namespace LIEF::PE::py {

template<>
void create<ResourceDialogExtended>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<ResourceDialogExtended, ResourceDialog> dialog(m, "ResourceDialogExtended",
      R"delim(
      Implementation for the new extended dialogbox format.

      See: https://learn.microsoft.com/en-us/windows/win32/dlgbox/dlgtemplateex
      )delim"_doc);

  init_ref_iterator<ResourceDialogExtended::it_items>(dialog, "it_items");

  nb::class_<ResourceDialogExtended::font_t>(dialog, "font_t",
    R"doc(
    Font information for the font to use for the text in the dialog box and
    its controls
    )doc"_doc
  )
    .def_rw("point_size", &ResourceDialogExtended::font_t::point_size,
            "The point size of the font"_doc)
    .def_rw("weight", &ResourceDialogExtended::font_t::weight,
            "The weight of the font"_doc)
    .def_rw("italic", &ResourceDialogExtended::font_t::italic,
            "Indicates whether the font is italic"_doc)
    .def_rw("charset", &ResourceDialogExtended::font_t::charset,
            "The character set to be used"_doc)
    .def_rw("typeface", &ResourceDialogExtended::font_t::typeface,
            "The name of the typeface for the font."_doc)
    .def("__bool__", &ResourceDialogExtended::font_t::is_defined)
    LIEF_DEFAULT_STR(ResourceDialogExtended::font_t);

  nb::class_<ResourceDialogExtended::Item, ResourceDialog::Item>(dialog, "Item",
      R"doc(
      This class represents a ``DLGTEMPLATEEX`` item (``DLGITEMTEMPLATEEX``).

      See: https://learn.microsoft.com/en-us/windows/win32/dlgbox/dlgitemtemplateex
      )doc"_doc)
    .def(nb::init<>())

    .def_prop_rw("help_id", nb::overload_cast<>(&ResourceDialogExtended::Item::help_id, nb::const_),
                            nb::overload_cast<uint32_t>(&ResourceDialogExtended::Item::help_id),
      R"doc(
      The help context identifier for the control. When the system sends a
      ``WM_HELP`` message, it passes the ``helpID`` value in the ``dwContextId``
      member of the ``HELPINFO`` structure.
      )doc"_doc
    )

    LIEF_DEFAULT_STR(ResourceDialogExtended::Item);

  dialog
    .def(nb::init<>())
    .def_prop_ro("version", nb::overload_cast<>(&ResourceDialogExtended::version, nb::const_),
      R"doc(
      The version number of the extended dialog box template. This member must
      be set to 1.
      )doc"_doc)

    .def_prop_ro("signature", nb::overload_cast<>(&ResourceDialogExtended::signature, nb::const_),
      R"doc(
      Indicates whether a template is an extended dialog box template.
      If signature is 0xFFFF, this is an extended dialog box template.
      In this case, the dlgVer member specifies the template version number.
      )doc"_doc)

    .def_prop_ro("help_id", nb::overload_cast<>(&ResourceDialogExtended::help_id, nb::const_),
      R"doc(
      The help context identifier for the dialog box window. When the system
      sends a ``WM_HELP`` message, it passes the ``helpID`` value in the
      ``dwContextId`` member of the ``HELPINFO`` structure.
      )doc"_doc)

    .def_prop_ro("items", nb::overload_cast<>(&ResourceDialogExtended::items),
                 "Iterator over the different control items"_doc,
                 nb::keep_alive<0, 1>())

    .def_prop_ro("font", nb::overload_cast<>(&ResourceDialogExtended::font, nb::const_),
                 "Additional font information"_doc)

    .def("add_item", &ResourceDialogExtended::add_item,
         "item"_a, "Add a new control item to the dialog"_doc)

  LIEF_DEFAULT_STR(ResourceDialogExtended);

}
}

