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
#include "pyIterator.hpp"

#include "LIEF/PE/resources/ResourceDialog.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/set.h>
#include "nanobind/extra/stl/u16string.h"

namespace LIEF::PE::py {

template<>
void create<ResourceDialog>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<ResourceDialog, LIEF::Object> dialog(m, "ResourceDialog",
      R"delim(
      Representation of a dialog box.

      Windows allows two kinds of dialog box:

        * Simple one
        * Extended one

      :attr:`~lief.PE.ResourceDialog.is_extended` can be used to determine which one is implemented
      )delim"_doc);

  init_ref_iterator<ResourceDialog::it_const_items>(dialog, "it_const_items");

  dialog
    .def_prop_ro("is_extended",
        &ResourceDialog::is_extended,
        "``True`` if the dialog is an extended one"_doc)

    .def_prop_ro("version",
        &ResourceDialog::version,
        "The version number of the extended dialog box template. This member must be set to 1."_doc)

    .def_prop_ro("signature",
        &ResourceDialog::signature,
        R"delim(
        Indicate whether a template is an extended dialog box template:

          * ``0xFFFF``: Extended dialog box template
          * Other value: Standard dialog box template
        )delim"_doc)

    .def_prop_ro("help_id",
        &ResourceDialog::version,
        "The help context identifier for the dialog box window"_doc)

    .def_prop_ro("x",
        nb::overload_cast<>(&ResourceDialog::x, nb::const_),
        "The x-coordinate, in dialog box units, of the upper-left corner of the dialog box."_doc)

    .def_prop_ro("y",
        nb::overload_cast<>(&ResourceDialog::y, nb::const_),
        "The y-coordinate, in dialog box units, of the upper-left corner of the dialog box."_doc)

    .def_prop_ro("cx",
        nb::overload_cast<>(&ResourceDialog::cx, nb::const_),
        "The width, in dialog box units, of the dialog box."_doc)

    .def_prop_ro("cy",
        nb::overload_cast<>(&ResourceDialog::cy, nb::const_),
        "The height, in dialog box units, of the dialog box."_doc)

    .def_prop_ro("title",
        nb::overload_cast<>(&ResourceDialog::title, nb::const_),
        "The title of the dialog box"_doc)

    .def_prop_ro("typeface",
        nb::overload_cast<>(&ResourceDialog::typeface, nb::const_),
        "The name of the typeface for the font"_doc)

    .def_prop_ro("weight",
        nb::overload_cast<>(&ResourceDialog::weight, nb::const_),
        "The weight of the font"_doc)

    .def_prop_ro("point_size",
        nb::overload_cast<>(&ResourceDialog::point_size, nb::const_),
        "The point size of the font to use for the text in the dialog box and its controls."_doc)

    .def_prop_ro("charset",
        nb::overload_cast<>(&ResourceDialog::charset, nb::const_),
        "The character set to be used"_doc)

    .def_prop_ro("style_list",
        &ResourceDialog::style_list,
        "Return list of " RST_CLASS_REF(lief.PE.WINDOW_STYLES) " associated with the "
        ":attr:`~lief.PE.ResourceDialog.style` member"_doc)

    .def_prop_ro("dialogbox_style_list",
        &ResourceDialog::dialogbox_style_list,
        "Return list of " RST_CLASS_REF(lief.PE.DIALOG_BOX_STYLES) " associated with the "
        ":attr:`~lief.PE.ResourceDialog.style` member"_doc)

    .def_prop_ro("extended_style_list",
        &ResourceDialog::dialogbox_style_list,
        "Return list of " RST_CLASS_REF(lief.PE.EXTENDED_WINDOW_STYLES) " associated with the "
        ":attr:`~lief.PE.ResourceDialog.extended_style` member"_doc)

    .def_prop_ro("style",
        &ResourceDialog::extended_style,
        "The style of the dialog box. This member can be a combination of "
        RST_CLASS_REF(lief.PE.WINDOW_STYLES) " and " RST_CLASS_REF(lief.PE.DIALOG_BOX_STYLES) ""_doc)

    .def_prop_ro("extended_style",
        &ResourceDialog::extended_style,
        "The extended windows styles (" RST_CLASS_REF(lief.PE.EXTENDED_WINDOW_STYLES) ")"_doc)

    .def_prop_ro("items",
        &ResourceDialog::items,
        "Iterator over the controls (" RST_CLASS_REF(lief.PE.ResourceDialogItem) ") that defines the Dialog (Button, Label...)"_doc,
        nb::keep_alive<0, 1>())

    .def("has_style",
        &ResourceDialog::has_style,
        "Check if the :attr:`~lief.PE.ResourceDialog.style` member has the given "
        "" RST_CLASS_REF(lief.PE.WINDOW_STYLES) ""_doc,
        "style"_a)

    .def("has_dialogbox_style",
        &ResourceDialog::has_dialogbox_style,
        "Check if the :attr:`~lief.PE.ResourceDialog.style` member has the given "
        "" RST_CLASS_REF(lief.PE.DIALOG_BOX_STYLES) ""_doc,
        "style"_a)

    .def("has_extended_style",
        &ResourceDialog::has_extended_style,
        "Check if the :attr:`~lief.PE.ResourceDialog.extended_style` member has the given "
        "" RST_CLASS_REF(lief.PE.EXTENDED_WINDOW_STYLES) ""_doc,
        "style"_a)

    .def_prop_rw("lang",
        nb::overload_cast<>(&ResourceDialog::lang, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceDialog::lang),
        "Primary language associated with the dialog"_doc)

    .def_prop_rw("sub_lang",
        nb::overload_cast<>(&ResourceDialog::sub_lang, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceDialog::sub_lang),
        "Secondary language associated with the dialog"_doc)

    LIEF_DEFAULT_STR(ResourceDialog);
}
}

