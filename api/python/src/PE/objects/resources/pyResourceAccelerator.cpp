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
#include <sstream>
#include <string>
#include <nanobind/stl/string.h>

#include "PE/pyPE.hpp"

#include "LIEF/PE/resources/ResourceAccelerator.hpp"
#include "enums_wrapper.hpp"

namespace LIEF::PE::py {

template<>
void create<ResourceAccelerator>(nb::module_& m) {
  create<ACCELERATOR_CODES>(m);

  nb::class_<ResourceAccelerator, LIEF::Object> obj(m, "ResourceAccelerator");
  enum_<ResourceAccelerator::FLAGS>(obj, "FLAGS", nb::is_flag(),
    R"doc(
    From: https://docs.microsoft.com/en-us/windows/win32/menurc/acceltableentry
    )doc"_doc
  )
    .value("VIRTKEY", ResourceAccelerator::FLAGS::VIRTKEY,
      R"doc(
      The accelerator key is a virtual-key code. If this flag is not specified,
      the accelerator key is assumed to specify an ASCII character code.
      )doc"_doc)

    .value("NOINVERT", ResourceAccelerator::FLAGS::NOINVERT,
      R"doc(
      A menu item on the menu bar is not highlighted when an accelerator is
      used. This attribute is obsolete and retained only for backward
      compatibility with resource files designed for 16-bit Windows.
      )doc"_doc)

    .value("SHIFT", ResourceAccelerator::FLAGS::SHIFT,
      R"doc(
      The accelerator is activated only if the user presses the SHIFT key.
      This flag applies only to virtual keys.
      )doc"_doc)

    .value("CONTROL", ResourceAccelerator::FLAGS::CONTROL,
      R"doc(
      The accelerator is activated only if the user presses the CTRL key.
      This flag applies only to virtual keys.
      )doc"_doc)

    .value("ALT", ResourceAccelerator::FLAGS::ALT,
      R"doc(
      The accelerator is activated only if the user presses the ALT key.
      This flag applies only to virtual keys.
      )doc"_doc)

    .value("END", ResourceAccelerator::FLAGS::END,
      R"doc(
      The entry is last in an accelerator table.
      )doc"_doc)
  ;

  obj
    .def_prop_ro("flags",
      nb::overload_cast<>(&ResourceAccelerator::flags, nb::const_),
      "Describe the keyboard accelerator characteristics."_doc)

    .def_prop_ro("ansi",
      nb::overload_cast<>(&ResourceAccelerator::ansi, nb::const_),
      "An ANSI character value or a virtual-key code that identifies the accelerator key."_doc)

    .def_prop_ro("ansi_str",
      nb::overload_cast<>(&ResourceAccelerator::ansi_str, nb::const_))

    .def_prop_ro("id",
      nb::overload_cast<>(&ResourceAccelerator::id, nb::const_),
      "An identifier for the keyboard accelerator."_doc)

    .def_prop_ro("padding",
      nb::overload_cast<>(&ResourceAccelerator::padding, nb::const_),
      "The number of bytes inserted to ensure that the structure is aligned on a DWORD boundary."_doc)

    .def("has", &ResourceAccelerator::has,
         "Whether the entry has the given flag"_doc)

    .def("add", &ResourceAccelerator::add,
         "Append the given flag"_doc)

    .def("remove", &ResourceAccelerator::remove,
         "Remove the given flag"_doc)

    LIEF_DEFAULT_STR(ResourceAccelerator);
}
}
