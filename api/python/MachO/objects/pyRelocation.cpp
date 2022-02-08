/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (Relocation::*)(void) const;

template<class T>
using setter_t = void (Relocation::*)(T);


template<>
void create<Relocation>(py::module& m) {

  py::class_<Relocation, LIEF::Relocation>(m, "Relocation",
      R"delim(
      It extends the LIEF :class:`lief.Relocation` abstract class and it is sub-classed by

      1. :class:`~lief.MachO.RelocationObject`
      2. :class:`~lief.MachO.RelocationDyld`
      )delim")

    .def_property("address",
        static_cast<getter_t<uint64_t>>(&Relocation::address),
        static_cast<setter_t<uint64_t>>(&Relocation::address),
        R"delim(
        For :attr:`~lief.MachO.FILE_TYPES.OBJECT` or (:attr:`~lief.MachO.Relocation.origin` is :attr:`~lief.MachO.RELOCATION_ORIGINS.RELOC_TABLE`) this is an "
        offset from the start of the :class:`~lief.MachO.Section`
        to the item containing the address requiring relocation.

        For :attr:`~lief.MachO.FILE_TYPES.EXECUTE` / :attr:`~lief.MachO.FILE_TYPES.DYLIB` or
        (:attr:`~lief.MachO.Relocation.origin` is :attr:`~lief.MachO.RELOCATION_ORIGINS.DYLDINFO`)
        this is a :attr:`~lief.MachO.SegmentCommand.virtual_address`.
        )delim")

    .def_property("pc_relative",
        static_cast<getter_t<bool>>(&Relocation::is_pc_relative),
        static_cast<setter_t<bool>>(&Relocation::pc_relative),
        R"delim(
        Indicates whether the item containing the address to be
        relocated is part of a CPU instruction that uses PC-relative addressing.

        For addresses contained in PC-relative instructions, the CPU adds the address of
        the instruction to the address contained in the instruction.
        )delim")

    .def_property("type",
        static_cast<getter_t<uint8_t>>(&Relocation::type),
        static_cast<setter_t<uint8_t>>(&Relocation::type),
        R"delim(
        Type of the relocation according to the :attr:`~lief.MachO.Relocation.architecture` and/or :attr:`~lief.MachO.Relocation.origin`

        If :attr:`~lief.MachO.Relocation.origin` is :attr:`~lief.MachO.RELOCATION_ORIGINS.RELOC_TABLE`:

        See:

          * :class:`lief.MachO.X86_RELOCATION`
          * :class:`lief.MachO.X86_64_RELOCATION`
          * :class:`lief.MachO.PPC_RELOCATION`
          * :class:`lief.MachO.ARM_RELOCATION`
          * :class:`lief.MachO.ARM64_RELOCATION`

        If :attr:`~lief.MachO.Relocation.origin` is :attr:`~lief.MachO.RELOCATION_ORIGINS.DYLDINFO`,
        the value is associated with :class:`~lief.MachO.REBASE_TYPES`.
        )delim")

    .def_property_readonly("architecture",
        &Relocation::architecture,
        "" RST_CLASS_REF(lief.MachO.CPU_TYPES) " of the relocation")

    .def_property_readonly("has_symbol",
        &Relocation::has_symbol,
        "``True`` if the relocation has a " RST_CLASS_REF(lief.MachO.Symbol) " associated with")

    .def_property_readonly("symbol",
        static_cast<Symbol* (Relocation::*)(void)>(&Relocation::symbol),
        "" RST_CLASS_REF(lief.MachO.Symbol) " associated with the relocation if any, or None",
        py::return_value_policy::reference)

    .def_property_readonly("has_section",
        &Relocation::has_section,
        "``True`` if the relocation has a " RST_CLASS_REF(lief.MachO.Section) " associated with")

    .def_property_readonly("section",
        static_cast<Section* (Relocation::*)(void)>(&Relocation::section),
        "" RST_CLASS_REF(lief.MachO.Section) " associated with the relocation if any, or None",
        py::return_value_policy::reference)


    .def_property_readonly("origin",
        &Relocation::origin,
        R"delim(
        :class:`~lief.MachO.RELOCATION_ORIGINS` of the relocation

        * For :attr:`~lief.MachO.FILE_TYPES.OBJECT` file it should be :attr:`~lief.MachO.RELOCATION_ORIGINS.RELOC_TABLE`
        * For :attr:`~lief.MachO.FILE_TYPES.EXECUTE` or :attr:`~lief.MachO.FILE_TYPES.DYLIB` it should be :attr:`~lief.MachO.RELOCATION_ORIGINS.DYLDINFO`")
        )delim")

    .def_property_readonly("has_segment",
        &Relocation::has_segment,
        "``True`` if the relocation has a " RST_CLASS_REF(lief.MachO.SegmentCommand) " associated with")

    .def_property_readonly("segment",
        static_cast<SegmentCommand* (Relocation::*)(void)>(&Relocation::segment),
        "" RST_CLASS_REF(lief.MachO.SegmentCommand) " associated with the relocation if any, or None",
        py::return_value_policy::reference)

    .def("__eq__", &Relocation::operator==)
    .def("__ne__", &Relocation::operator!=)
    .def("__hash__",
        [] (const Relocation& relocation) {
          return Hash::hash(relocation);
        })


    .def("__str__",
        [] (const Relocation& relocation)
        {
          std::ostringstream stream;
          stream << relocation;
          std::string str = stream.str();
          return str;
        });

}

}
}
