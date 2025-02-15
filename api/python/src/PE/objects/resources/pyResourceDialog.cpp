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
#include "enums_wrapper.hpp"

#include "LIEF/PE/resources/ResourceDialog.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

#include "PE/ordinal_or_str.hpp"
#include "nanobind/extra/stl/u16string.h"
#include "nanobind/extra/stl/lief_span.h"

namespace LIEF::PE::py {

template<>
void create<ResourceDialog>(nb::module_& m) {
  nb::class_<ResourceDialog, LIEF::Object> dialog(m, "ResourceDialog",
      R"delim(
      This class is the base class for either a regular (legacy) Dialog or
      an extended Dialog. These different kinds of Dialogs are documented by MS
      at the following addresses:

      - https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-dlgtemplate
      - https://learn.microsoft.com/fr-fr/windows/win32/dlgbox/dlgitemtemplateex
      )delim"_doc);

  #define ENTRY(X) .value(to_string(ResourceDialog::DIALOG_STYLES::X), ResourceDialog::DIALOG_STYLES::X)
  enum_<ResourceDialog::DIALOG_STYLES>(dialog, "DIALOG_STYLES", nb::is_flag(),
    "From: https://learn.microsoft.com/en-us/windows/win32/dlgbox/dialog-box-styles"_doc
  )
    ENTRY(ABSALIGN)
    ENTRY(SYSMODAL)
    ENTRY(LOCALEDIT)
    ENTRY(SETFONT)
    ENTRY(MODALFRAME)
    ENTRY(NOIDLEMSG)
    ENTRY(SETFOREGROUND)
    ENTRY(S3DLOOK)
    ENTRY(FIXEDSYS)
    ENTRY(NOFAILCREATE)
    ENTRY(CONTROL)
    ENTRY(CENTER)
    ENTRY(CENTERMOUSE)
    ENTRY(CONTEXTHELP)
    ENTRY(SHELLFONT)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(ResourceDialog::WINDOW_STYLES::X), ResourceDialog::WINDOW_STYLES::X)
  enum_<ResourceDialog::WINDOW_STYLES>(dialog, "WINDOW_STYLES", nb::is_flag(),
    "From: https://docs.microsoft.com/en-us/windows/win32/winmsg/window-styles"_doc
  )
    ENTRY(OVERLAPPED)
    ENTRY(POPUP)
    ENTRY(CHILD)
    ENTRY(MINIMIZE)
    ENTRY(VISIBLE)
    ENTRY(DISABLED)
    ENTRY(CLIPSIBLINGS)
    ENTRY(CLIPCHILDREN)
    ENTRY(MAXIMIZE)
    ENTRY(CAPTION)
    ENTRY(BORDER)
    ENTRY(DLGFRAME)
    ENTRY(VSCROLL)
    ENTRY(HSCROLL)
    ENTRY(SYSMENU)
    ENTRY(THICKFRAME)
    ENTRY(GROUP)
    ENTRY(TABSTOP)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(ResourceDialog::WINDOW_EXTENDED_STYLES::X), ResourceDialog::WINDOW_EXTENDED_STYLES::X)
  enum_<ResourceDialog::WINDOW_EXTENDED_STYLES>(dialog, "WINDOW_EXTENDED_STYLES", nb::is_flag(),
    "From: https://docs.microsoft.com/en-us/windows/win32/winmsg/extended-window-styles"_doc
  )
    ENTRY(DLGMODALFRAME)
    ENTRY(NOPARENTNOTIFY)
    ENTRY(TOPMOST)
    ENTRY(ACCEPTFILES)
    ENTRY(TRANSPARENT_STY)
    ENTRY(MDICHILD)
    ENTRY(TOOLWINDOW)
    ENTRY(WINDOWEDGE)
    ENTRY(CLIENTEDGE)
    ENTRY(CONTEXTHELP)
    ENTRY(RIGHT)
    ENTRY(LEFT)
    ENTRY(RTLREADING)
    ENTRY(LEFTSCROLLBAR)
    ENTRY(CONTROLPARENT)
    ENTRY(STATICEDGE)
    ENTRY(APPWINDOW)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(ResourceDialog::CONTROL_STYLES::X), ResourceDialog::CONTROL_STYLES::X)
  enum_<ResourceDialog::CONTROL_STYLES>(dialog, "CONTROL_STYLES", nb::is_flag(),
    "From: https://learn.microsoft.com/en-us/windows/win32/controls/common-control-styles"_doc
  )
    ENTRY(TOP)
    ENTRY(NOMOVEY)
    ENTRY(BOTTOM)
    ENTRY(NORESIZE)
    ENTRY(NOPARENTALIGN)
    ENTRY(ADJUSTABLE)
    ENTRY(NODIVIDER)
    ENTRY(VERT)
    ENTRY(LEFT)
    ENTRY(RIGHT)
    ENTRY(NOMOVEX)
  ;
  #undef ENTRY

  nb::enum_<ResourceDialog::TYPE>(dialog, "TYPE",
    R"doc(
    Enum for discriminating the kind of the Dialog (regular vs extended)
    )doc"_doc
  )
    .value("UNKNOWN", ResourceDialog::TYPE::UNKNOWN)
    .value("REGULAR", ResourceDialog::TYPE::REGULAR)
    .value("EXTENDED", ResourceDialog::TYPE::EXTENDED);

  nb::class_<ResourceDialog::Item>(dialog, "Item")
    .def_prop_rw("style",
                 nb::overload_cast<>(&ResourceDialog::Item::style, nb::const_),
                 nb::overload_cast<uint32_t>(&ResourceDialog::Item::style),
                 nb::rv_policy::reference_internal,
      R"doc(
      The style of the control. This can be a combination of :class:`~.WINDOW_STYLES`
      or :class:`~.CONTROL_STYLES`.
      )doc"_doc
    )

    .def_prop_rw("extended_style",
                 nb::overload_cast<>(&ResourceDialog::Item::extended_style, nb::const_),
                 nb::overload_cast<uint32_t>(&ResourceDialog::Item::extended_style),
                 nb::rv_policy::reference_internal,
      R"doc(
      The extended styles for a window. This member is not used to create
      controls in dialog boxes, but applications that use dialog box templates
      can use it to create other types of windows.

      It can take a combination of :class:`~.WINDOW_EXTENDED_STYLES`
      )doc"_doc
    )

    .def_prop_rw("id",
                 nb::overload_cast<>(&ResourceDialog::Item::id, nb::const_),
                 nb::overload_cast<int32_t>(&ResourceDialog::Item::id),
                 nb::rv_policy::reference_internal,
                 "The control identifier."_doc
    )

    .def_prop_rw("x",
                 nb::overload_cast<>(&ResourceDialog::Item::x, nb::const_),
                 nb::overload_cast<int16_t>(&ResourceDialog::Item::x),
                 nb::rv_policy::reference_internal,
      R"doc(
      The x-coordinate, in dialog box units, of the upper-left corner of the
      control. This coordinate is always relative to the upper-left corner of
      the dialog box's client area.
      )doc"_doc
    )

    .def_prop_rw("y",
                 nb::overload_cast<>(&ResourceDialog::Item::y, nb::const_),
                 nb::overload_cast<int16_t>(&ResourceDialog::Item::y),
                 nb::rv_policy::reference_internal,
      R"doc(
      The y-coordinate, in dialog box units, of the upper-left corner of the
      control. This coordinate is always relative to the upper-left corner of
      the dialog box's client area.
      )doc"_doc
    )

    .def_prop_rw("cx",
                 nb::overload_cast<>(&ResourceDialog::Item::cx, nb::const_),
                 nb::overload_cast<int16_t>(&ResourceDialog::Item::cx),
                 nb::rv_policy::reference_internal,
                 "The width, in dialog box units, of the control."_doc)

    .def_prop_rw("cy",
                 nb::overload_cast<>(&ResourceDialog::Item::cy, nb::const_),
                 nb::overload_cast<int16_t>(&ResourceDialog::Item::cy),
                 nb::rv_policy::reference_internal,
                 "The height, in dialog box units, of the control."_doc)

    .def("has", nb::overload_cast<ResourceDialog::WINDOW_STYLES>(&ResourceDialog::Item::has, nb::const_),
         "style"_a, "Check if this item has the given :class:`~.WINDOW_STYLES`"_doc)

    .def("has", nb::overload_cast<ResourceDialog::CONTROL_STYLES>(&ResourceDialog::Item::has, nb::const_),
         "style"_a, "Check if this item has the given :class:`~.CONTROL_STYLES`"_doc)

    .def_prop_ro("window_styles", &ResourceDialog::Item::window_styles,
                 "List of :class:`~.WINDOW_STYLES` used by this item"_doc)

    .def_prop_ro("control_styles", &ResourceDialog::Item::control_styles,
                 "List of :class:`~.CONTROL_STYLES` used by this item"_doc)

    .def_prop_ro("clazz", nb::overload_cast<>(&ResourceDialog::Item::clazz, nb::const_),
      R"doc(
      Window class of the control. This can be either: a string that specifies
      the name of a registered window class or an ordinal value of a predefined
      system class.
      )doc"_doc)

    .def_prop_ro("title", nb::overload_cast<>(&ResourceDialog::Item::title, nb::const_),
      R"doc(
      Title of the item which can be either: a string that specifies the
      initial text or an ordinal value of a resource, such as an icon, in an
      executable file
      )doc"_doc)

    .def_prop_ro("creation_data", nb::overload_cast<>(&ResourceDialog::Item::creation_data, nb::const_),
      "Creation data that is passed to the control's window procedure"_doc)

    LIEF_DEFAULT_STR(ResourceDialog::Item);
  ;

  dialog
    .def_prop_ro("type", &ResourceDialog::type)
    .def_prop_rw("style",
                 nb::overload_cast<>(&ResourceDialog::style, nb::const_),
                 nb::overload_cast<uint32_t>(&ResourceDialog::style),
                 nb::rv_policy::reference_internal,
      R"doc(
      The style of the dialog box. This member can be a combination of window
      style values (such as :attr:`~.WINDOW_STYLES.CAPTION` and
      :attr:`~.WINDOW_STYLES.SYSMENU`) and dialog box style values
      (such as :attr:`~.DIALOG_STYLES.CENTER`).
      )doc"_doc
    )

    .def_prop_rw("extended_style",
                 nb::overload_cast<>(&ResourceDialog::extended_style, nb::const_),
                 nb::overload_cast<uint32_t>(&ResourceDialog::extended_style),
                 nb::rv_policy::reference_internal,
      R"doc(
      The extended styles for a window. This member is not used to create dialog
      boxes, but applications that use dialog box templates can use it to create
      other types of windows. For a list of values, see :class:`~.WINDOW_EXTENDED_STYLES`
      )doc"_doc
    )

    .def_prop_rw("x",
                 nb::overload_cast<>(&ResourceDialog::x, nb::const_),
                 nb::overload_cast<int16_t>(&ResourceDialog::x),
                 nb::rv_policy::reference_internal,
      R"doc(
      The x-coordinate, in dialog box units, of the upper-left corner of the
      dialog box.
      )doc"_doc
    )

    .def_prop_rw("y",
                 nb::overload_cast<>(&ResourceDialog::y, nb::const_),
                 nb::overload_cast<int16_t>(&ResourceDialog::y),
                 nb::rv_policy::reference_internal,
      R"doc(
      The y-coordinate, in dialog box units, of the upper-left corner of the
      dialog box.
      )doc"_doc
    )

    .def_prop_rw("cx",
                 nb::overload_cast<>(&ResourceDialog::cx, nb::const_),
                 nb::overload_cast<int16_t>(&ResourceDialog::cx),
                 nb::rv_policy::reference_internal,
      "The width, in dialog box units, of the dialog box."_doc
    )

    .def_prop_rw("cy",
                 nb::overload_cast<>(&ResourceDialog::cy, nb::const_),
                 nb::overload_cast<int16_t>(&ResourceDialog::cy),
                 nb::rv_policy::reference_internal,
      "The height, in dialog box units, of the dialog box"_doc
    )

    .def("has", nb::overload_cast<ResourceDialog::DIALOG_STYLES>(&ResourceDialog::has, nb::const_),
         "Check if the dialog used to given dialog style"_doc)

    .def("has", nb::overload_cast<ResourceDialog::WINDOW_STYLES>(&ResourceDialog::has, nb::const_),
         "Check if the dialog used to given window style"_doc)

    .def("has", nb::overload_cast<ResourceDialog::WINDOW_EXTENDED_STYLES>(&ResourceDialog::has, nb::const_),
         "Check if the dialog used to given extended window style"_doc)

    .def_prop_ro("styles_list", &ResourceDialog::styles_list,
                 "List of :class:`~.DIALOG_STYLES` used by this dialog"_doc)

    .def_prop_ro("windows_styles_list", &ResourceDialog::windows_styles_list,
                 "List of :class:`~.WINDOW_STYLES` used by this dialog"_doc)

    .def_prop_ro("windows_ext_styles_list", &ResourceDialog::windows_ext_styles_list,
                 "List of :class:`~.WINDOW_EXTENDED_STYLES` used by this dialog"_doc)

    .def_prop_rw("title", nb::overload_cast<>(&ResourceDialog::title_utf8, nb::const_),
                          nb::overload_cast<const std::string&>(&ResourceDialog::title),
                          nb::rv_policy::reference_internal,
                          "title of the dialog box"_doc)
    .def_prop_ro("menu", nb::overload_cast<>(&ResourceDialog::menu, nb::const_),
                 "ordinal or name value of a menu resource"_doc)

    .def_prop_ro("window_class", nb::overload_cast<>(&ResourceDialog::window_class, nb::const_),
      "ordinal of a predefined system window class or name of a registered window class"_doc
    )


  LIEF_CLONABLE(ResourceDialog)
  LIEF_DEFAULT_STR(ResourceDialog);
}
}

