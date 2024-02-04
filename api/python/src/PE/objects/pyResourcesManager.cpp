/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
 * Copyright 2017 - 2021 K. Nakagawa
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
#include "pyErr.hpp"
#include "pySafeString.hpp"

#include "LIEF/PE/ResourcesManager.hpp"
#include "LIEF/PE/ResourceNode.hpp"
#include "enums_wrapper.hpp"

#include <string>
#include <sstream>

#include <nanobind/stl/string.h>
#include <nanobind/stl/set.h>
#include <nanobind/stl/vector.h>

namespace LIEF::PE::py {

template<>
void create<ResourcesManager>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<ResourcesManager, LIEF::Object> manager(m, "ResourcesManager",
      "The Resource Manager provides an enhanced API to manipulate the resource tree"_doc);

  init_ref_iterator<ResourcesManager::it_const_dialogs>(manager, "it_const_dialogs");
  init_ref_iterator<ResourcesManager::it_const_icons>(manager, "it_const_icons");
  init_ref_iterator<ResourcesManager::it_const_strings_table>(manager, "it_const_strings_table");
  init_ref_iterator<ResourcesManager::it_const_accelerators>(manager, "it_const_accelerators");
  #define ENTRY(X) .value(to_string(ResourcesManager::TYPE::X), ResourcesManager::TYPE::X)
  enum_<ResourcesManager::TYPE>(manager, "TYPE")
    ENTRY(CURSOR)
    ENTRY(BITMAP)
    ENTRY(ICON)
    ENTRY(MENU)
    ENTRY(DIALOG)
    ENTRY(STRING)
    ENTRY(FONTDIR)
    ENTRY(FONT)
    ENTRY(ACCELERATOR)
    ENTRY(RCDATA)
    ENTRY(MESSAGETABLE)
    ENTRY(GROUP_CURSOR)
    ENTRY(GROUP_ICON)
    ENTRY(VERSION)
    ENTRY(DLGINCLUDE)
    ENTRY(PLUGPLAY)
    ENTRY(VXD)
    ENTRY(ANICURSOR)
    ENTRY(ANIICON)
    ENTRY(HTML)
    ENTRY(MANIFEST)
  ;
  #undef ENTRY

  manager
    .def(nb::init<ResourceNode&>(), nb::keep_alive<0, 1>())
    .def_prop_ro("has_manifest",
        &ResourcesManager::has_manifest,
        "``True`` if the resources contain a Manifest element"_doc)

    .def_prop_rw("manifest",
        [] (const ResourcesManager& obj) {
          return safe_string(obj.manifest());
        },
        nb::overload_cast<const std::string&>(&ResourcesManager::manifest),
        "Manifest as a ``string``"_doc)


    .def_prop_ro("has_version",
        &ResourcesManager::has_version,
        "``true`` if the resources contain a " RST_CLASS_REF(lief.PE.ResourceVersion) ""_doc)

    .def_prop_ro("version",
        [] (ResourcesManager& self) {
          return error_or(&ResourcesManager::version, self);
        },
        "Return the " RST_CLASS_REF(lief.PE.ResourceVersion) ""_doc)

    .def_prop_ro("has_icons",
        &ResourcesManager::has_icons,
        "``true`` if the resources contain " RST_CLASS_REF(lief.PE.ResourceIcon) ""_doc)

    .def_prop_ro("icons", &ResourcesManager::icons,
      "Return the list of the " RST_CLASS_REF(lief.PE.ResourceIcon) " present in the resource"_doc,
      nb::keep_alive<0, 1>())

    .def("change_icon",
        &ResourcesManager::change_icon,
        "Switch the given icons"_doc,
        "old_one"_a, "new_one"_a)

    .def_prop_ro("has_dialogs",
        &ResourcesManager::has_dialogs,
        "``true`` if the resources contain " RST_CLASS_REF(lief.PE.ResourceDialog) ""_doc)

    .def_prop_ro("dialogs",
      &ResourcesManager::dialogs,
      "Return the list of the " RST_CLASS_REF(lief.PE.ResourceDialog) " present in the resource"_doc,
      nb::keep_alive<0, 1>())

    .def_prop_ro("types",
      &ResourcesManager::get_types,
      "Return list of :class:`~.TYPE` present in the resources"_doc)

    .def("add_icon",
      &ResourcesManager::add_icon,
      "Add an icon to the resources"_doc,
      "icon"_a)

    .def("has_type",
      &ResourcesManager::has_type,
      "``True`` if the resource has the given :class:`~.TYPE`"_doc,
      "type"_a)

    .def_prop_ro("has_string_table",
      &ResourcesManager::has_string_table,
      "``True`` if resources contain " RST_CLASS_REF(lief.PE.ResourceStringTable) ""_doc)

    .def_prop_ro("string_table", &ResourcesManager::string_table,
      "Return list of " RST_CLASS_REF(lief.PE.ResourceStringTable) " present in the resource"_doc,
      nb::keep_alive<1, 0>())

    .def_prop_ro("has_html",
      &ResourcesManager::has_html,
      "``True`` if resources contain HTML resource"_doc)

    .def_prop_ro("html",
      &ResourcesManager::html,
      "HTML resource as the list of ``string``"_doc)

    .def_prop_ro("has_accelerator",
      &ResourcesManager::has_accelerator,
      "``True`` if resources contain " RST_CLASS_REF(lief.PE.ResourceAccelerator) ""_doc)

    .def_prop_ro("accelerator", &ResourcesManager::accelerator,
      "Return list of " RST_CLASS_REF(lief.PE.ResourceAccelerator) " present in the resource"_doc,
      nb::keep_alive<1, 0>())

    .def("get_node_type",
      nb::overload_cast<ResourcesManager::TYPE>(&ResourcesManager::get_node_type),
      R"delim(
      Return :class:`~lief.PE.ResourceNode` with the given :class:`~.TYPE`
      or None if not found.
      )delim"_doc,
      "type"_a,
      nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(ResourcesManager);
}
}
