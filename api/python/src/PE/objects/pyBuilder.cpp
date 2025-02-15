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

#include "pyErr.hpp"
#include "LIEF/PE/Builder.hpp"
#include "LIEF/PE/Binary.hpp"

#include <string>
#include <sstream>
#include "nanobind/utils.hpp"
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/function.h>

namespace LIEF::PE::py {

template<>
void create<Builder>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<Builder> builder(m, "Builder");

  nb::class_<Builder::config_t> config(builder, "config_t",
    R"doc(
    This structure is used to configure the build operation.

    The default value of these attributes is set to ``False`` if the
    operation modifies the binary layout even though nothing changed.
    For instance, building the import table **always** requires relocating the
    table to another place. Thus, the default value is false and must
    be explicitly set to true.
    )doc"_doc
  );
  config
    .def(nb::init<>())
    .def_rw("imports", &Builder::config_t::imports,
      R"doc(
      Whether the builder should reconstruct the imports table.
      This option should be turned on if you modify imports.

      Please check LIEF website for more details
      )doc"_doc)
    .def_rw("exports", &Builder::config_t::exports,
      R"doc(
      Whether the builder should reconstruct the export table
      This option should be turned on if you modify exports.

      Please check LIEF website for more details
      )doc"_doc)
    .def_rw("resources", &Builder::config_t::resources,
      R"doc(
      Whether the builder should regenerate the resources tree
      )doc"_doc)
    .def_rw("relocations", &Builder::config_t::relocations,
      R"doc(
      Whether the builder should regenerate relocations
      )doc"_doc)
    .def_rw("load_configuration", &Builder::config_t::load_configuration,
      R"doc(
      Whether the builder should regenerate the load configuration
      )doc"_doc)
    .def_rw("tls", &Builder::config_t::tls,
      R"doc(
      Whether the builder should regenerate the TLS info
      )doc"_doc)
    .def_rw("overlay", &Builder::config_t::overlay,
      R"doc(
      Whether the builder should write back any overlay data
      )doc"_doc)
    .def_rw("debug", &Builder::config_t::debug,
      R"doc(
      Whether the builder should regenerate debug entries
      )doc"_doc)
    .def_rw("dos_stub", &Builder::config_t::dos_stub,
      R"doc(
      Whether the builder should write back dos stub (including the rich header)
      )doc"_doc)

    .def_rw("rsrc_section", &Builder::config_t::rsrc_section,
      R"doc(
      If the resources tree needs to be relocated, this attribute defines the
      name of the new section that contains the relocated tree.
      )doc"_doc)

    .def_rw("idata_section", &Builder::config_t::idata_section,
      R"doc(
      Section that holds the relocated import table (IAT/ILT)
      )doc"_doc)

    .def_rw("tls_section", &Builder::config_t::tls_section,
      R"doc(
      Section that holds the relocated TLS info
      )doc"_doc)

    .def_rw("reloc_section", &Builder::config_t::reloc_section,
      R"doc(
      Section that holds the relocated relocations
      )doc"_doc)

    .def_rw("export_section", &Builder::config_t::export_section,
      R"doc(
      Section that holds the export table
      )doc"_doc)

    .def_rw("debug_section", &Builder::config_t::debug_section,
      R"doc(
      Section that holds the debug entries
      )doc"_doc)

    .def_rw("resolved_iat_cbk", &Builder::config_t::resolved_iat_cbk)
    .def_rw("force_relocating", &Builder::config_t::force_relocating)
  ;

  builder
    .def(nb::init<Binary&, const Builder::config_t&>(),
        "binary"_a, "config"_a)

    .def_prop_ro("rsrc_data", [] (const Builder& self) {
      return nb::to_memoryview(self.rsrc_data());
    })

    .def("build",
        [] (Builder& self) {
          return error_or(static_cast<ok_error_t(Builder::*)()>(&Builder::build), self);
        },
        "Perform the build process"_doc)

    .def("write",
        static_cast<void (Builder::*)(const std::string&) const>(&Builder::write),
        "Write the build result into the ``output`` file"_doc,
        "output"_a)

    .def("bytes", [] (Builder& self) -> nb::bytes {
          std::ostringstream out;
          self.write(out);
          return nb::to_bytes(out.str());
        })
    ;

}
}
