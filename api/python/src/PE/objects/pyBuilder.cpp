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

#include "pyErr.hpp"
#include "LIEF/PE/Builder.hpp"
#include "LIEF/PE/Binary.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::PE::py {

template<>
void create<Builder>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Builder>(m, "Builder",
      R"delim(
      Class that is used to rebuild a raw PE binary from a PE::Binary object
      )delim"_doc)

    .def(nb::init<Binary&>(),
        "Constructor that takes a " RST_CLASS_REF(lief.PE.Binary) ""_doc,
        "pe_binary"_a)

    .def("build",
        [] (Builder& self) {
          return error_or(static_cast<ok_error_t(Builder::*)()>(&Builder::build), self);
        },
        "Perform the build process"_doc)

    .def("build_imports",
        &Builder::build_imports,
        "Rebuild the import table into another section"_doc,
        nb::arg("enable") = true,
        nb::rv_policy::reference_internal)

    .def("patch_imports",
        &Builder::patch_imports,
        "Patch the original import table in order to redirect functions to "
        "the new import table.\n\n"
        "This setting should be used with ``build_imports`` set to ``True``"_doc,
        nb::arg("enable") = true,
        nb::rv_policy::reference_internal)

    .def("build_relocations",
        &Builder::build_relocations,
        "Rebuild the relocation table in another section"_doc,
        nb::arg("enable") = true,
        nb::rv_policy::reference_internal)

    .def("build_tls",
        static_cast<Builder& (Builder::*)(bool)>(&Builder::build_tls),
        "Rebuild TLS object in another section"_doc,
        nb::arg("enable") = true,
        nb::rv_policy::reference_internal)

    .def("build_resources",
        static_cast<Builder& (Builder::*)(bool)>(&Builder::build_resources),
        "Rebuid the resources in another section"_doc,
        nb::arg("enable") = true,
        nb::rv_policy::reference_internal)

    .def("build_overlay",
        static_cast<Builder& (Builder::*)(bool)>(&Builder::build_overlay),
        "Rebuild the binary's overlay"_doc,
        nb::arg("enable") = true,
        nb::rv_policy::reference_internal)

    .def("build_dos_stub",
        static_cast<Builder& (Builder::*)(bool)>(&Builder::build_dos_stub),
        "Rebuild the DOS stub"_doc,
        nb::arg("enable") = true,
        nb::rv_policy::reference_internal)

    .def("write",
        static_cast<void (Builder::*)(const std::string&) const>(&Builder::write),
        "Write the build result into the ``output`` file"_doc,
        "output"_a)

    .def("get_build",
        &Builder::get_build,
        "Return the build result as a ``list`` of bytes"_doc,
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(Builder);
}
}
