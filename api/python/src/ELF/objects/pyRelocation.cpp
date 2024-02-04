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
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

#include "ELF/pyELF.hpp"
#include "enums_wrapper.hpp"

#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/Section.hpp"

namespace LIEF::ELF::py {

void init_relocation_types(nb::class_<Relocation, LIEF::Relocation>& m);

template<>
void create<Relocation>(nb::module_& m) {
  nb::class_<Relocation, LIEF::Relocation> reloc(m, "Relocation",
      R"delim(
      Class that represents an ELF relocation.
      )delim"_doc);

  init_relocation_types(reloc);

  enum_<Relocation::PURPOSE>(reloc, "PURPOSE")
    .value("NONE", Relocation::PURPOSE::NONE)
    .value("PLTGOT", Relocation::PURPOSE::PLTGOT)
    .value("DYNAMIC", Relocation::PURPOSE::DYNAMIC)
    .value("OBJECT", Relocation::PURPOSE::OBJECT);

  enum_<Relocation::ENCODING>(reloc, "ENCODING")
    .value("UNKNOWN", Relocation::ENCODING::UNKNOWN)
    .value("ANDROID_SLEB", Relocation::ENCODING::ANDROID_SLEB,
           "The relocation is using the packed Android-SLEB128 format"_doc)
    .value("REL", Relocation::ENCODING::REL,
           "The relocation is using the regular Elf_Rel structure"_doc)
    .value("RELR", Relocation::ENCODING::RELR,
           "The relocation is using the relative relocation format"_doc)
    .value("RELA", Relocation::ENCODING::RELA,
           "The relocation is using the regular Elf_Rela structure"_doc);

  reloc
    .def(nb::init<>())
    .def(nb::init<ARCH>(), "arch"_a)
    .def(nb::init<uint64_t, Relocation::TYPE, Relocation::ENCODING>(),
        "address"_a, "type"_a, "encoding"_a)

    .def_prop_rw("addend",
        nb::overload_cast<>(&Relocation::addend, nb::const_),
        nb::overload_cast<int64_t>(&Relocation::addend),
        "Additional value"_doc)

    .def_prop_rw("info",
        nb::overload_cast<>(&Relocation::info, nb::const_),
        nb::overload_cast<uint32_t>(&Relocation::info),
        "Extra information like the symbol index"_doc)

    .def_prop_rw("purpose",
        nb::overload_cast<>(&Relocation::purpose, nb::const_),
        nb::overload_cast<Relocation::PURPOSE>(&Relocation::purpose),
        R"delim(
        Purpose of the relocation.
        This value provides the information about how the relocation is used (PLT/GOT resolution, ``.o`` file, ...)
        )delim"_doc)

    .def_prop_rw("type",
        nb::overload_cast<>(&Relocation::type, nb::const_),
        nb::overload_cast<Relocation::TYPE>(&Relocation::type),
        R"delim(Relocation type.)delim"_doc)

    .def_prop_ro("has_symbol",
        &Relocation::has_symbol,
        "``True`` if a " RST_CLASS_REF(lief.ELF.Symbol) " is associated with the relocation"_doc)

    .def_prop_rw("symbol",
        nb::overload_cast<>(&Relocation::symbol, nb::const_),
        nb::overload_cast<Symbol*>(&Relocation::symbol),
        R"delim(
        :class:`~lief.ELF.Symbol` associated with the relocation or None
        if no symbol are associated with this relocation.
        )delim"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_section",
        &Relocation::has_section,
        R"delim(
        ``True`` if this relocation has a :class:`lief.ELF.Section` associated with.

        This is usually the case for object files (``.o``)
        )delim"_doc)

    .def_prop_ro("section",
        nb::overload_cast<>(&Relocation::section),
        R"delim(
        :class:`~lief.ELF.Section` in which the relocation is applied or None if not relevant
        )delim"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("symbol_table",
      nb::overload_cast<>(&Relocation::symbol_table),
      R"delim(
      the symbol table :class:`~lief.ELF.Section` which the relocation references
      )delim"_doc,
      nb::rv_policy::reference_internal)

    .def_prop_ro("is_rela",
      &Relocation::is_rela,
      "``True`` if the relocation **uses** the :attr:`~lief.ELF.Relocation.addend` proprety"_doc)

    .def_prop_ro("is_rel",
      &Relocation::is_rel,
      "``True`` if the relocation **doesn't use** the :attr:`~lief.ELF.Relocation.addend` proprety"_doc)

    .def("r_info", &Relocation::r_info,
      R"delim(
      (re)Compute the raw ``r_info`` attribute based on the given ELF class
      )delim"_doc, "clazz"_a)

    .def_prop_ro("is_relatively_encoded", &Relocation::is_relatively_encoded,
                 "True if the relocation is using the relative encoding"_doc)

    .def_prop_ro("is_android_packed", &Relocation::is_android_packed,
                 "True if the relocation is using the Android packed relocation format"_doc)

    .def_prop_ro("is_rel", &Relocation::is_rel,
        R"delim(
        Check if the relocation uses the implicit addend
        (i.e. not present in the ELF structure)
        )delim"_doc)

    .def_prop_ro("encoding", &Relocation::encoding,
                 "The encoding of the relocation")

    LIEF_DEFAULT_STR(Relocation);
}

}
