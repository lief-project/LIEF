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

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Builder.hpp"

namespace LIEF::ELF::py {

template<>
void create<Builder>(nb::module_& m) {
  nb::class_<Builder> builder(m, "Builder",
      R"delim(
      Class which takes an :class:`lief.ELF.Binary` object and reconstructs a valid binary
      )delim"_doc);

  nb::class_<Builder::config_t>(builder, "config_t",
                                "Interface to tweak the " RST_CLASS_REF(lief.ELF.Builder) ""_doc)
    .def(nb::init<>())
    .def_rw("force_relocate", &Builder::config_t::force_relocate,
            "Force to relocate all the ELF structures that can be relocated (mostly for testing)"_doc)

    .def_rw("dt_hash",         &Builder::config_t::dt_hash, "Rebuild :attr:`~lief.ELF.DynamicEntry.TAG.HASH`"_doc)
    .def_rw("dyn_str",         &Builder::config_t::dyn_str, "Rebuild :attr:`~lief.ELF.DynamicEntry.TAG.STRTAB`"_doc)
    .def_rw("dynamic_section", &Builder::config_t::dynamic_section, "Rebuild the `PT_DYNAMIC` segment"_doc)
    .def_rw("fini_array",      &Builder::config_t::fini_array, "Rebuild :attr:`~lief.ELF.DynamicEntry.TAG.FINI_ARRAY`"_doc)
    .def_rw("init_array",      &Builder::config_t::init_array, "Rebuild :attr:`~lief.ELF.DynamicEntry.TAG.INIT_ARRAY`"_doc)
    .def_rw("interpreter",     &Builder::config_t::interpreter, "Rebuild  the `PT_INTERP` segment"_doc)
    .def_rw("jmprel",          &Builder::config_t::jmprel, "Rebuild :attr:`~lief.ELF.DynamicEntry.TAG.JMPREL`"_doc)
    .def_rw("notes",           &Builder::config_t::notes, "Rebuild `PT_NOTES` segment(s)"_doc)
    .def_rw("preinit_array",   &Builder::config_t::preinit_array, "Rebuild :attr:`~lief.ELF.DynamicEntry.TAG.PREINIT_ARRAY`"_doc)
    .def_rw("relr",            &Builder::config_t::relr, "Rebuild :attr:`~lief.ELF.DynamicEntry.TAG.RELR`"_doc)
    .def_rw("android_rela",    &Builder::config_t::android_rela, "Rebuild :attr:`~lief.ELF.DynamicEntry.TAG.ANDROID_RELA`"_doc)
    .def_rw("rela",            &Builder::config_t::rela, "Rebuild :attr:`~lief.ELF.DynamicEntry.TAG.RELA`"_doc)
    .def_rw("static_symtab",   &Builder::config_t::static_symtab, "Rebuild `.symtab` section"_doc)
    .def_rw("sym_verdef",      &Builder::config_t::sym_verdef, "Rebuild :attr:`~lief.ELF.DynamicEntry.TAG.VERDEF`"_doc)
    .def_rw("sym_verneed",     &Builder::config_t::sym_verneed, "Rebuild :attr:`~lief.ELF.DynamicEntry.TAG.VERNEED`"_doc)
    .def_rw("sym_versym",      &Builder::config_t::sym_versym, "Rebuild :attr:`~lief.ELF.DynamicEntry.TAG.VERSYM`"_doc)
    .def_rw("symtab",          &Builder::config_t::symtab, "Rebuild :attr:`~lief.ELF.DynamicEntry.TAG.SYMTAB`"_doc)
    .def_rw("coredump_notes",  &Builder::config_t::coredump_notes, "Rebuild the Coredump notes"_doc);

  builder
    .def(nb::init<Binary&>(),
        "Constructor that takes a " RST_CLASS_REF(lief.ELF.Binary) ""_doc,
        "elf_binary"_a)

    .def("build",
        [] (Builder& self) {
          return self.build();
        },
        "Perform the build of the provided ELF binary"_doc)

    .def_prop_rw("config", &Builder::config, &Builder::set_config,
        "Tweak the ELF builder with the provided config parameter"_doc,
        nb::rv_policy::reference_internal)

    .def("write",
        nb::overload_cast<const std::string&>(&Builder::write, nb::const_),
        "Write the build result into the ``output`` file"_doc,
        "output"_a)

    .def("get_build",
        &Builder::get_build,
        "Return the build result as a ``list`` of bytes"_doc,
        nb::rv_policy::reference_internal);

}
}

