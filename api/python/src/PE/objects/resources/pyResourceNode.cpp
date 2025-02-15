
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
#include "pySafeString.hpp"

#include "LIEF/utils.hpp"
#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"

#include <string>
#include <sstream>

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/operators.h>

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
    .def_static("parse", [] (nb::bytes bytes, uint64_t rva) {
        return ResourceNode::parse((const uint8_t*)bytes.data(), bytes.size(), rva);
      },
      R"doc(
      Parse the resource tree from the provided bytes and
      with the original RVA provided in the second parameter.

      The RVA value should be come from the :attr:`lief.PE.DataDirectory.rva` associated with
      the resource tree.
      )doc"_doc,
      "bytes"_a, "rva"_a, nb::rv_policy::take_ownership
    )

    .def_prop_rw("id",
      nb::overload_cast<>(&ResourceNode::id, nb::const_),
      nb::overload_cast<uint32_t>(&ResourceNode::id),
      "Integer that identifies the Type, Name, or Language ID entry."_doc
    )

    .def_prop_ro("is_directory", &ResourceNode::is_directory,
      "``True`` if the current node is a :class:`~.ResourceDirectory`"_doc
    )

    .def_prop_ro("is_data", &ResourceNode::is_data,
      "``True`` if the current node is a :class:`~.ResourceData`"_doc
    )

    .def_prop_ro("has_name", &ResourceNode::has_name,
      "``True`` if the current node uses a name"_doc
    )

    .def_prop_rw("name",
      &ResourceNode::utf8_name,
      nb::overload_cast<const std::string&>(&ResourceNode::name),
      "Resource's name"_doc
    )

    .def_prop_ro("childs", nb::overload_cast<>(&ResourceNode::childs),
      "Node's children"_doc, nb::keep_alive<0, 1>()
    )

    .def("add_child",
      nb::overload_cast<const ResourceNode&>(&ResourceNode::add_child),
      "Add a new child to the current node"_doc,
      "node"_a, nb::rv_policy::reference_internal
    )

    .def("delete_child",
      nb::overload_cast<const ResourceNode&>(&ResourceNode::delete_child),
      "Delete the given :class:`~.ResourceNode` from the current children"_doc,
      "node"_a
    )

    .def("delete_child",
      nb::overload_cast<uint32_t>(&ResourceNode::delete_child),
      R"doc(
      Delete the :class:`~.ResourceNode` with the given :attr:`~.ResourceNode.id`
      from the current children
      )doc"_doc, "id"_a
    )

    .def_prop_ro("depth", &ResourceNode::depth,
      "Current depth of the node in the resource tree"_doc
    )

    .def("__eq__", [] (const ResourceNode& lhs, const ResourceNode& rhs) {
      return lhs == rhs;
    }, nb::is_operator())

    .def("__ne__", [] (const ResourceNode& lhs, const ResourceNode& rhs) {
      return lhs != rhs;
    }, nb::is_operator())

    LIEF_CLONABLE(ResourceNode)
    LIEF_DEFAULT_STR(ResourceNode);
}
}
