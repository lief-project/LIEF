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

#include "LIEF/PE/debug/CodeViewPDB.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/array.h>

#include "pySafeString.hpp"

namespace LIEF::PE::py {

template<>
void create<CodeViewPDB>(nb::module_& m) {
  nb::class_<CodeViewPDB, CodeView>(m, "CodeViewPDB",
    R"delim(CodeView PDB specialization)delim"_doc)
    .def(nb::init<>())

    .def_prop_ro("parent",
        [] (nb::object& self) -> nb::object {
          auto* ab = nb::cast<CodeViewPDB*>(self);
          const nb::handle base_type = nb::type<CodeView>();
          nb::object py_inst = nb::inst_reference(base_type, ab, self);
          nb::inst_set_state(py_inst, /*ready=*/true, /*destruct=*/false);
          return py_inst;
        },
        R"delim(
        Return a reference to the parent :class:`lief.PE.CodeView`
        )delim"_doc,
        "parent(self) -> lief.PE.CodeView"_p,
        nb::rv_policy::reference_internal)

    .def_prop_ro("guid", &CodeViewPDB::guid,
      R"doc(
      The GUID signature to verify against the .pdb file signature.

      This attribute might be used to lookup remote PDB file on a symbol server
      )doc"_doc
    )

    .def_prop_rw("signature",
        nb::overload_cast<>(&CodeViewPDB::signature, nb::const_),
        nb::overload_cast<const CodeViewPDB::signature_t&>(&CodeViewPDB::signature),
        R"doc(
        The 32-bit signature to verify against the .pdb file signature.
        )doc"_doc)

    .def_prop_rw("age",
        nb::overload_cast<>(&CodeViewPDB::age, nb::const_),
        nb::overload_cast<uint32_t>(&CodeViewPDB::age),
        R"doc(
        Age value to verify. The age does not necessarily correspond to any known
        time value, it is used to determine if a .pdb file is out of sync with
        a corresponding .exe file.
        )doc"_doc)

    .def_prop_rw("filename",
        [] (const CodeViewPDB& self) {
          return LIEF::py::safe_string(self.filename());
        },
        nb::overload_cast<std::string>(&CodeViewPDB::filename),
        "The path to the ``.pdb`` file"_doc)

    LIEF_DEFAULT_STR(CodeViewPDB);
}

}
