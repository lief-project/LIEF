/* Copyright 2022 - 2026 R. Thomas
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
#include "LIEF/DebugDeclOpt.hpp"
#include "pyLIEF.hpp"

#include <string>

#include <nanobind/stl/string.h>
#include <nanobind/stl/unordered_map.h>

namespace LIEF::py {
template<>
void create<DeclOpt>(nb::module_& m) {
  nb::class_<DeclOpt>(m, "DeclOpt",
    R"doc(
    Configuration options for generated code from debug info.

    This structure configures how the debug information (DWARF/PDB) translated
    into an AST is generated. You can use it to configure the indentation, and
    the information to generate when translating DWARF/PDB into C++-like
    definitions
    )doc"_doc)

    .def(nb::init<>())

    .def_prop_rw("indentation",
      nb::overload_cast<>(&DeclOpt::indentation, nb::const_),
      nb::overload_cast<uint32_t>(&DeclOpt::indentation),
      "The number of spaces for indentation."_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("is_cpp",
      nb::overload_cast<>(&DeclOpt::is_cpp, nb::const_),
      nb::overload_cast<bool>(&DeclOpt::is_cpp),
      R"doc(
      Prefer C++ syntax over C syntax.

      If true, the output will use C++ features (e.g., ``bool`` keyword)
      )doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("show_extended_annotations",
      nb::overload_cast<>(&DeclOpt::show_extended_annotations, nb::const_),
      nb::overload_cast<bool>(&DeclOpt::show_extended_annotations),
      R"doc(
      Enable extended comments and annotations.

      If true, the generated code will include comments containing low-level
      details such as memory addresses, offsets, type sizes, and original
      source locations.
      )doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("include_types",
      nb::overload_cast<>(&DeclOpt::include_types, nb::const_),
      nb::overload_cast<bool>(&DeclOpt::include_types),
      R"doc(
      Include full type definitions.

      If true, the output will contain the full definition of types (structs,
      enums, unions).
      )doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("include_locals",
      nb::overload_cast<>(&DeclOpt::include_locals, nb::const_),
      nb::overload_cast<bool>(&DeclOpt::include_locals),
      R"doc(
      Emit a function body listing its local / stack variables.
      )doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("desugar",
      nb::overload_cast<>(&DeclOpt::desugar, nb::const_),
      nb::overload_cast<bool>(&DeclOpt::desugar),
      R"doc(
      Resolve type aliases (sugar).

      If true, typedef and type aliases are replaced by their underlying
      canonical types (e.g., ``uint32_t`` might become ``unsigned int``).
      )doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("show_field_offsets",
      nb::overload_cast<>(&DeclOpt::show_field_offsets, nb::const_),
      nb::overload_cast<bool>(&DeclOpt::show_field_offsets),
      R"doc(
      Show the relative offset of each field/attribute in structures.

      If true, every member of a structure is prefixed with its byte offset
      (e.g. ``/* 0x04 */``).
      )doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("type_aliases",
      nb::overload_cast<>(&DeclOpt::type_aliases, nb::const_),
      nb::overload_cast<DeclOpt::type_aliases_t>(&DeclOpt::type_aliases),
      R"doc(
      Mapping of type names to user-friendly aliases used while
      rendering types (e.g.
      ``std::basic_string<char, ...>`` -> ``std::string``).
      )doc"_doc,
      nb::rv_policy::reference_internal
    )

    .def("add_type_alias",
      [] (DeclOpt& self, std::string name, std::string alias) -> DeclOpt& {
        return self.add_type_alias(std::move(name), std::move(alias));
      },
      "name"_a, "alias"_a,
      "Register a single type alias (see :attr:`~.type_aliases`)."_doc,
      nb::rv_policy::reference_internal
    )
  ;
}
}
