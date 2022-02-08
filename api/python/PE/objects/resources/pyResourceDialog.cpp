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
#include "pyIterators.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/resources/ResourceDialog.hpp"

#include <string>
#include <sstream>


namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (ResourceDialog::*)(void) const;

template<class T>
using setter_t = void (ResourceDialog::*)(T);


template<>
void create<ResourceDialog>(py::module& m) {
  py::class_<ResourceDialog, LIEF::Object> dialog(m, "ResourceDialog",
      R"delim(
      Representation of a dialog box.

      Windows allows two kinds of dialog box:

        * Simple one
        * Extended one

      :attr:`~lief.PE.ResourceDialog.is_extended` can be used to determine which one is implemented
      )delim");

  init_ref_iterator<ResourceDialog::it_const_items>(dialog, "it_const_items");

  dialog
    .def_property_readonly("is_extended",
        &ResourceDialog::is_extended,
        "``True`` if the dialog is an extended one")

    .def_property_readonly("version",
        &ResourceDialog::version,
        "The version number of the extended dialog box template. This member must be set to 1.")

    .def_property_readonly("signature",
        &ResourceDialog::signature,
        R"delim(
        Indicate whether a template is an extended dialog box template:

          * ``0xFFFF``: Extended dialog box template
          * Other value: Standard dialog box template
        )delim")

    .def_property_readonly("help_id",
        &ResourceDialog::version,
        "The help context identifier for the dialog box window")

    .def_property_readonly("x",
        static_cast<getter_t<int16_t>>(&ResourceDialog::x),
        "The x-coordinate, in dialog box units, of the upper-left corner of the dialog box.")

    .def_property_readonly("y",
        static_cast<getter_t<int16_t>>(&ResourceDialog::y),
        "The y-coordinate, in dialog box units, of the upper-left corner of the dialog box.")

    .def_property_readonly("cx",
        static_cast<getter_t<int16_t>>(&ResourceDialog::cx),
        "The width, in dialog box units, of the dialog box.")

    .def_property_readonly("cy",
        static_cast<getter_t<int16_t>>(&ResourceDialog::cy),
        "The height, in dialog box units, of the dialog box.")

    .def_property_readonly("title",
        static_cast<getter_t<const std::u16string&>>(&ResourceDialog::title),
        "The title of the dialog box")

    .def_property_readonly("typeface",
        static_cast<getter_t<const std::u16string&>>(&ResourceDialog::typeface),
        "The name of the typeface for the font")

    .def_property_readonly("weight",
        static_cast<getter_t<uint16_t>>(&ResourceDialog::weight),
        "The weight of the font")

    .def_property_readonly("point_size",
        static_cast<getter_t<uint16_t>>(&ResourceDialog::point_size),
        "The point size of the font to use for the text in the dialog box and its controls.")

    .def_property_readonly("charset",
        static_cast<getter_t<uint8_t>>(&ResourceDialog::charset),
        "The character set to be used")

    .def_property_readonly("style_list",
        &ResourceDialog::style_list,
        "Return list of " RST_CLASS_REF(lief.PE.WINDOW_STYLES) " associated with the "
        ":attr:`~lief.PE.ResourceDialog.style` member")

    .def_property_readonly("dialogbox_style_list",
        &ResourceDialog::dialogbox_style_list,
        "Return list of " RST_CLASS_REF(lief.PE.DIALOG_BOX_STYLES) " associated with the "
        ":attr:`~lief.PE.ResourceDialog.style` member")

    .def_property_readonly("extended_style_list",
        &ResourceDialog::dialogbox_style_list,
        "Return list of " RST_CLASS_REF(lief.PE.EXTENDED_WINDOW_STYLES) " associated with the "
        ":attr:`~lief.PE.ResourceDialog.extended_style` member")

    .def_property_readonly("style",
        &ResourceDialog::extended_style,
        "The style of the dialog box. This member can be a combination of "
        RST_CLASS_REF(lief.PE.WINDOW_STYLES) " and " RST_CLASS_REF(lief.PE.DIALOG_BOX_STYLES) "")

    .def_property_readonly("extended_style",
        &ResourceDialog::extended_style,
        "The extended windows styles (" RST_CLASS_REF(lief.PE.EXTENDED_WINDOW_STYLES) ")")

    .def_property_readonly("items",
        &ResourceDialog::items,
        "Iterator over the controls (" RST_CLASS_REF(lief.PE.ResourceDialogItem) ") that defines the Dialog (Button, Label...)")

    .def("has_style",
        &ResourceDialog::has_style,
        "Check if the :attr:`~lief.PE.ResourceDialog.style` member has the given "
        "" RST_CLASS_REF(lief.PE.WINDOW_STYLES) "",
        "style"_a)

    .def("has_dialogbox_style",
        &ResourceDialog::has_dialogbox_style,
        "Check if the :attr:`~lief.PE.ResourceDialog.style` member has the given "
        "" RST_CLASS_REF(lief.PE.DIALOG_BOX_STYLES) "",
        "style"_a)

    .def("has_extended_style",
        &ResourceDialog::has_extended_style,
        "Check if the :attr:`~lief.PE.ResourceDialog.extended_style` member has the given "
        "" RST_CLASS_REF(lief.PE.EXTENDED_WINDOW_STYLES) "",
        "style"_a)

    .def_property("lang",
        static_cast<getter_t<RESOURCE_LANGS>>(&ResourceDialog::lang),
        static_cast<setter_t<RESOURCE_LANGS>>(&ResourceDialog::lang),
        "Primary " RST_CLASS_REF(lief.PE.RESOURCE_LANGS) " associated with the dialog")

    .def_property("sub_lang",
        static_cast<getter_t<RESOURCE_SUBLANGS>>(&ResourceDialog::sub_lang),
        static_cast<setter_t<RESOURCE_SUBLANGS>>(&ResourceDialog::sub_lang),
        "Secondary " RST_CLASS_REF(lief.PE.RESOURCE_SUBLANGS) " associated with the dialog")

    .def("__eq__", &ResourceDialog::operator==)
    .def("__ne__", &ResourceDialog::operator!=)
    .def("__hash__",
        [] (const ResourceDialog& dialog) {
          return Hash::hash(dialog);
        })

    .def("__str__",
        [] (const ResourceDialog& dialog) {
          std::ostringstream stream;
          stream << dialog;
          std::string str = stream.str();
          return str;
        });
}

}
}

