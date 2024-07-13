
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
#include "pySafeString.hpp"

#include "LIEF/utils.hpp"
#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"

#include <string>
#include <sstream>

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::PE::py {

template<>
void create<ResourceNode>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<ResourceNode, LIEF::Object> res_node(m, "ResourceNode",
      R"delim(
      Class which represents a Node in the resource tree.
      It is extended by :class:`lief.PE.ResourceData` and :class:`lief.PE.ResourceNode`
      )delim"_doc);

  init_ref_iterator<ResourceNode::it_childs>(res_node, "it_childs");

  res_node
    .def_prop_rw("id",
        nb::overload_cast<>(&ResourceNode::id, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceNode::id),
        "Integer that identifies the Type, Name, or "
        "Language ID entry."_doc)

    .def_prop_ro("is_directory", &ResourceNode::is_directory,
        "``True`` if the current resource is a " RST_CLASS_REF(lief.PE.ResourceDirectory) ""_doc)

    .def_prop_ro("is_data", &ResourceNode::is_data,
        "``True`` if the current resource is a " RST_CLASS_REF(lief.PE.ResourceData) ""_doc)

    .def_prop_ro("has_name", &ResourceNode::has_name,
        "``True`` if the current resource uses a name"_doc)

    .def_prop_rw("name",
        [] (const ResourceNode& node) {
          return safe_string(LIEF::u16tou8(node.name()));
        },
        nb::overload_cast<const std::string&>(&ResourceNode::name),
        "Resource's name"_doc)

    .def_prop_ro("childs", nb::overload_cast<>(&ResourceNode::childs),
        "Node's childs"_doc,
        nb::keep_alive<0, 1>())

    .def("add_directory_node",
        nb::overload_cast<const ResourceDirectory&>(&ResourceNode::add_child),
        "Add a " RST_CLASS_REF(lief.PE.ResourceDirectory) " to the current node"_doc,
        "resource_directory"_a,
        nb::rv_policy::reference_internal)

    .def("add_data_node",
        nb::overload_cast<const ResourceData&>(&ResourceNode::add_child),
        "Add a " RST_CLASS_REF(lief.PE.ResourceData) " to the current node"_doc,
        "resource_data"_a,
        nb::rv_policy::reference_internal)

    .def("delete_child",
        nb::overload_cast<const ResourceNode&>(&ResourceNode::delete_child),
        "Delete the given " RST_CLASS_REF(lief.PE.ResourceNode) " from childs"_doc,
        "node"_a)

    .def("delete_child",
        nb::overload_cast<uint32_t>(&ResourceNode::delete_child),
        "Delete the " RST_CLASS_REF(lief.PE.ResourceNode) " with the given :attr:`~lief.PE.ResourceNode.id` from childs"_doc,
        "id"_a)

    .def_prop_ro("depth",
        &ResourceNode::depth,
        "Current depth of the entry in the resource tree"_doc)

    LIEF_CLONABLE(ResourceNode)
    LIEF_DEFAULT_STR(ResourceNode);
}
}
