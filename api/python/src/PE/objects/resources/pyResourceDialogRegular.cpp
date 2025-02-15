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

#include "LIEF/PE/resources/ResourceDialogRegular.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include "nanobind/extra/stl/u16string.h"

namespace LIEF::PE::py {

template<>
void create<ResourceDialogRegular>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<ResourceDialogRegular, ResourceDialog> dialog(m, "ResourceDialogRegular",
      R"doc(
      Implementation for a regular/legacy dialog box.

      See: https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-dlgtemplate
      )doc"_doc);

  init_ref_iterator<ResourceDialogRegular::it_items>(dialog, "it_items");

  nb::class_<ResourceDialogRegular::font_t>(dialog, "font_t",
    R"doc(
    This structure represents additional font information that might be
    embedded at the end of the DLGTEMPLATE stream
    )doc"_doc
  )
    .def_rw("point_size", &ResourceDialogRegular::font_t::point_size)
    .def_rw("name", &ResourceDialogRegular::font_t::name)
    .def("__bool__", &ResourceDialogRegular::font_t::is_defined)
    LIEF_DEFAULT_STR(ResourceDialogRegular::font_t);

  nb::class_<ResourceDialogRegular::Item, ResourceDialog::Item>(dialog, "Item",
      R"doc(
      This class represents a ``DLGTEMPLATE`` item (``DLGITEMTEMPLATE``)
      See: https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-dlgitemtemplate
      )doc"_doc)
    .def(nb::init<>())

    LIEF_DEFAULT_STR(ResourceDialogRegular::Item);

  dialog
    .def(nb::init<>())

    .def_prop_ro("nb_items", &ResourceDialogRegular::nb_items,
                 "Number of control items"_doc)

    .def_prop_ro("items", nb::overload_cast<>(&ResourceDialogRegular::items),
                 "Iterator over the different control items"_doc,
                 nb::keep_alive<0, 1>())

    .def_prop_ro("font", nb::overload_cast<>(&ResourceDialogRegular::font, nb::const_),
                 "Additional font information"_doc)

    .def("add_item", &ResourceDialogRegular::add_item,
         "item"_a, "Add a new control item to the dialog"_doc)


  LIEF_DEFAULT_STR(ResourceDialogRegular);


}
}

