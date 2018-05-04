/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include "LIEF/utils.hpp"
#include "LIEF/PE/ResourceNode.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (ResourceNode::*)(void) const;

template<class T>
using setter_t = void (ResourceNode::*)(T);

void init_PE_ResourceNode_class(py::module& m) {
  py::class_<ResourceNode, LIEF::Object>(m, "ResourceNode")

    .def_property("id",
        static_cast<getter_t<uint32_t>>(&ResourceNode::id),
        static_cast<setter_t<uint32_t>>(&ResourceNode::id),
        "Integer that identifies the Type, Name, or "
        "Language ID entry.")

    .def_property_readonly("is_directory",
        &ResourceNode::is_directory,
        "``True`` if the current resource is a " RST_CLASS_REF(lief.PE.ResourceDirectory) "")

    .def_property_readonly("is_data",
        &ResourceNode::is_data,
        "``True`` if the current resource is a " RST_CLASS_REF(lief.PE.ResourceData) "")

    .def_property_readonly("has_name",
        &ResourceNode::has_name,
        "``True`` if the current resource uses a name")

    .def_property("name",
        [] (const ResourceNode& node) {
          return safe_string_converter(LIEF::u16tou8(node.name()));
        },
        static_cast<void (ResourceNode::*)(const std::string&)>(&ResourceNode::name),
        "Resource name")

    .def_property_readonly("childs",
        static_cast<it_childs (ResourceNode::*)(void)>(&ResourceNode::childs),
        "Node's childs")

    .def("add_directory_node",
        static_cast<ResourceNode& (ResourceNode::*)(const ResourceDirectory&)>(&ResourceNode::add_child),
        "Add a " RST_CLASS_REF(lief.PE.ResourceDirectory) " to the current node",
        "resource_directory"_a)

    .def("add_data_node",
        static_cast<ResourceNode& (ResourceNode::*)(const ResourceData&)>(&ResourceNode::add_child),
        "Add a " RST_CLASS_REF(lief.PE.ResourceData) " to the current node",
        "resource_data"_a)

    .def("delete_child",
        static_cast<void (ResourceNode::*)(const ResourceNode&)>(&ResourceNode::delete_child),
        "Delete the given " RST_CLASS_REF(lief.PE.ResourceNode) " from childs",
        "node"_a)

    .def("delete_child",
        static_cast<void (ResourceNode::*)(uint32_t)>(&ResourceNode::delete_child),
        "Delete the " RST_CLASS_REF(lief.PE.ResourceNode) " with the given :attr:`~lief.PE.ResourceNode.id` from childs",
        "id"_a)

    .def("sort_by_id",
        &ResourceNode::sort_by_id,
        "Sort resource childs by ID")

    .def_property_readonly("depth",
        &ResourceNode::depth,
        "Current depth of the entry in the resource tree")

    .def("__eq__", &ResourceNode::operator==)
    .def("__ne__", &ResourceNode::operator!=)

    .def("__hash__",
        [] (const ResourceNode& node) {
          return Hash::hash(node);
        })

    .def("__str__",
        [] (const ResourceNode& node) {
          std::ostringstream stream;
          stream << node;
          std::string str = stream.str();
          return str;
        });



}
