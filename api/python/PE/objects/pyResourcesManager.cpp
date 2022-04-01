/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "pyPE.hpp"
#include "pyIterators.hpp"
#include "pyErr.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/ResourcesManager.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (ResourcesManager::*)(void) const;

template<class T>
using setter_t = void (ResourcesManager::*)(T);

template<class T, class P>
using no_const_func = T (ResourcesManager::*)(P);


template<>
void create<ResourcesManager>(py::module& m) {
  py::class_<ResourcesManager, LIEF::Object> manager(m, "ResourcesManager",
      "The Resource Manager provides an enhanced API to manipulate the resource tree");

  init_ref_iterator<ResourcesManager::it_const_dialogs>(manager, "it_const_dialogs");
  init_ref_iterator<ResourcesManager::it_const_icons>(manager, "it_const_icons");
  init_ref_iterator<ResourcesManager::it_const_strings_table>(manager, "it_const_strings_table");
  init_ref_iterator<ResourcesManager::it_const_accelerators>(manager, "it_const_accelerators");

  manager
    .def_property_readonly("has_manifest",
        &ResourcesManager::has_manifest,
        "``True`` if the resources contain a Manifest element")

    .def_property("manifest",
        [] (const ResourcesManager& obj) {
          return safe_string_converter(obj.manifest());
        },
        static_cast<setter_t<const std::string&>>(&ResourcesManager::manifest),
        "Manifest as a ``string``")


    .def_property_readonly("has_version",
        &ResourcesManager::has_version,
        "``true`` if the resources contain a " RST_CLASS_REF(lief.PE.ResourceVersion) "")

    .def_property_readonly("version",
        [] (ResourcesManager& self) {
          return error_or(&ResourcesManager::version, self);
        },
        "Return the " RST_CLASS_REF(lief.PE.ResourceVersion) "")

    .def_property_readonly("has_icons",
        &ResourcesManager::has_icons,
        "``true`` if the resources contain " RST_CLASS_REF(lief.PE.ResourceIcon) "")

    .def_property_readonly("icons",
      &ResourcesManager::icons,
      "Return the list of the " RST_CLASS_REF(lief.PE.ResourceIcon) " present in the resource")

    .def("change_icon",
        &ResourcesManager::change_icon,
        "Switch the given icons",
        "old_one"_a, "new_one"_a)

    .def_property_readonly("has_dialogs",
        &ResourcesManager::has_dialogs,
        "``true`` if the resources contain " RST_CLASS_REF(lief.PE.ResourceDialog) "")

    .def_property_readonly("dialogs",
      &ResourcesManager::dialogs,
      "Return the list of the " RST_CLASS_REF(lief.PE.ResourceDialog) " present in the resource")

    .def_property_readonly("types_available",
      &ResourcesManager::get_types_available,
      "Return list of " RST_CLASS_REF(lief.PE.RESOURCE_TYPES) " present in the resources")

    .def_property_readonly("langs_available",
      &ResourcesManager::get_langs_available,
      "Return list of " RST_CLASS_REF(lief.PE.RESOURCE_LANGS) " present in the resources")

    .def_property_readonly("sublangs_available",
      &ResourcesManager::get_sublangs_available,
      "Return list of " RST_CLASS_REF(lief.PE.RESOURCE_SUBLANGS) " present in the resources")

    .def("add_icon",
      &ResourcesManager::add_icon,
      "Add an icon to the resources",
      "icon"_a)

    .def("has_type",
      &ResourcesManager::has_type,
      "``True`` if the resource has the given " RST_CLASS_REF(lief.PE.RESOURCE_TYPES) "",
      "type"_a)

    .def_property_readonly("has_string_table",
      &ResourcesManager::has_string_table,
      "``True`` if resources contain " RST_CLASS_REF(lief.PE.ResourceStringTable) "")

    .def_property_readonly("string_table",
      &ResourcesManager::string_table,
      "Return list of " RST_CLASS_REF(lief.PE.ResourceStringTable) " present in the resource")

    .def_property_readonly("has_html",
      &ResourcesManager::has_html,
      "``True`` if resources contain HTML resource")

    .def_property_readonly("html",
      &ResourcesManager::html,
      "HTML resource as the list of ``string``")

    .def_property_readonly("has_accelerator",
      &ResourcesManager::has_accelerator,
      "``True`` if resources contain " RST_CLASS_REF(lief.PE.ResourceAccelerator) "")

    .def_property_readonly("accelerator",
      &ResourcesManager::accelerator,
      "Return list of " RST_CLASS_REF(lief.PE.ResourceAccelerator) " present in the resource")

    .def("get_node_type",
      static_cast<no_const_func<ResourceNode*, RESOURCE_TYPES>>(&ResourcesManager::get_node_type),
      R"delim(
      Return :class:`~lief.PE.ResourceNode` with the given :class:`~lief.PE.RESOURCE_TYPES`
      or None if not found.
      )delim",
      "type"_a,
      py::return_value_policy::reference)

    .def("__str__",
        [] (const ResourcesManager& manager) {
          std::ostringstream stream;
          stream << manager;
          std::string str = stream.str();
          return str;
        });
}
}
}

