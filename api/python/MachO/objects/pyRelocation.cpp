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
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/visitors/Hash.hpp"
#include "LIEF/MachO/Relocation.hpp"

#include "pyMachO.hpp"

template<class T>
using getter_t = T (Relocation::*)(void) const;

template<class T>
using setter_t = void (Relocation::*)(T);


void init_MachO_Relocation_class(py::module& m) {

  py::class_<Relocation>(m, "Relocation")

    .def_property("address",
        static_cast<getter_t<uint32_t>>(&Relocation::address),
        static_cast<setter_t<uint32_t>>(&Relocation::address),
        "For :attr:`~lief.MachO.FILE_TYPES.OBJECT` this is an "
        "offset from the start of the " RST_CLASS_REF(lief.MachO.Section) " "
        "to the item containing the address requiring relocation.",
        py::return_value_policy::reference_internal)

    .def_property("pc_relative",
        static_cast<getter_t<bool>>(&Relocation::is_pc_relative),
        static_cast<setter_t<bool>>(&Relocation::pc_relative),
        "Indicates whether the item containing the address to be "
        "relocated is part of a CPU instruction that uses PC-relative addressing.\n\n"

        "For addresses contained in PC-relative instructions, the CPU adds the address of "
        "the instruction to the address contained in the instruction.",
        py::return_value_policy::reference_internal)

    .def_property("size",
        static_cast<getter_t<uint8_t>>(&Relocation::size),
        static_cast<setter_t<uint8_t>>(&Relocation::size),
        "Indicates the length of the item containing the address to be relocated.\n\n"

        "The following table lists values and the corresponding address length:\n"
        "\t * 0: 1 byte\n"
        "\t * 1: 2 byte\n"
        "\t * 2: 4 byte\n"
        "\t * 3: 4 byte\n",
        py::return_value_policy::reference_internal)

    .def_property("type",
        static_cast<getter_t<uint8_t>>(&Relocation::type),
        static_cast<setter_t<uint8_t>>(&Relocation::type),
        "Type of the relocation according to the :attr:`~lief.MachO.Relocation.architecture`\n\n"

        "See:\n"
        "\t * " RST_CLASS_REF(lief.MachO.X86_RELOCATION)    "\n"
        "\t * " RST_CLASS_REF(lief.MachO.X86_64_RELOCATION) "\n"
        "\t * " RST_CLASS_REF(lief.MachO.PPC_RELOCATION)    "\n"
        "\t * " RST_CLASS_REF(lief.MachO.ARM_RELOCATION)    "\n"
        "\t * " RST_CLASS_REF(lief.MachO.ARM64_RELOCATION)  "\n",
        py::return_value_policy::reference_internal)

    .def_property("value",
        static_cast<getter_t<int32_t>>(&Relocation::value),
        static_cast<setter_t<int32_t>>(&Relocation::value),
        "For **scattered** relocations, the address of the relocatable expression "
        "for the item in the file that needs to be updated if the address is changed.\n\n"

        "For relocatable expressions with the difference of two section addresses, "
        "the address from which to subtract (in mathematical terms, the minuend) "
        "is contained in the first relocation entry and the address to subtract (the subtrahend) "
        "is contained in the second relocation entry.",
        py::return_value_policy::reference_internal)


    .def_property_readonly("architecture",
        &Relocation::architecture,
        "" RST_CLASS_REF(lief.MachO.CPU_TYPES) " of the relocation")

    .def_property_readonly("is_scattered",
        &Relocation::is_scattered,
        "``True`` if the relocation is a scattered one")

    .def_property_readonly("has_symbol",
        &Relocation::has_symbol,
        "``True`` if the relocation has a " RST_CLASS_REF(lief.MachO.Symbol) " associated with")

    .def_property_readonly("symbol",
        static_cast<Symbol& (Relocation::*)(void)>(&Relocation::symbol),
        "" RST_CLASS_REF(lief.MachO.Symbol) " associated with the relocation (if any)",
        py::return_value_policy::reference)

    .def_property_readonly("has_section",
        &Relocation::has_section,
        "``True`` if the relocation has a " RST_CLASS_REF(lief.MachO.Section) " associated with")

    .def_property_readonly("section",
        static_cast<Section& (Relocation::*)(void)>(&Relocation::section),
        "" RST_CLASS_REF(lief.MachO.Section) " associated with the relocation (if any)",
        py::return_value_policy::reference)

    .def("__eq__", &Relocation::operator==)
    .def("__ne__", &Relocation::operator!=)
    .def("__hash__",
        [] (const Relocation& relocation) {
          return LIEF::Hash::hash(relocation);
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
