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
#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/Relocation.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (Relocation::*)(void) const;

template<class T>
using setter_t = void (Relocation::*)(T);

void init_ELF_Relocation_class(py::module& m) {
  // Relocation object
  py::class_<Relocation, LIEF::Relocation>(m, "Relocation")
    .def(py::init<>())
    .def(py::init<uint64_t, uint32_t, int64_t, bool>(),
        "address"_a, "type"_a = 0, "addend"_a = 0, "is_rela"_a = false)

    .def_property("addend",
        static_cast<getter_t<int64_t>>(&Relocation::addend),
        static_cast<setter_t<int64_t>>(&Relocation::addend),
        "Additional value")

    .def_property("purpose",
        static_cast<getter_t<RELOCATION_PURPOSES>>(&Relocation::purpose),
        static_cast<setter_t<RELOCATION_PURPOSES>>(&Relocation::purpose),
        "Purpose (" RST_CLASS_REF(lief.ELF.RELOCATION_PURPOSES) ") of the relocation")

    .def_property("type",
        static_cast<getter_t<uint32_t>>(&Relocation::type),
        static_cast<setter_t<uint32_t>>(&Relocation::type),
        "Relocation type.\n\n"
        "See:\n\n"
        "\t\t * " RST_CLASS_REF(lief.ELF.RELOCATION_X86_64) "\n\n"
        "\t\t * " RST_CLASS_REF(lief.ELF.RELOCATION_ARM) "\n\n"
        "\t\t * " RST_CLASS_REF(lief.ELF.RELOCATION_i386) "\n\n")

    .def_property_readonly("has_symbol",
        &Relocation::has_symbol,
        "``True`` if a " RST_CLASS_REF(lief.ELF.Symbol) " is associated with the relocations")

    .def_property_readonly("symbol",
        static_cast<Symbol& (Relocation::*)(void)>(&Relocation::symbol),
        "" RST_CLASS_REF(lief.ELF.Symbol) " associated with the relocation",
        py::return_value_policy::reference_internal)

    .def_property_readonly("has_section",
        &Relocation::has_section,
        "``True`` if a this relocation has a " RST_CLASS_REF(lief.ELF.Section) " associated")

    .def_property_readonly("section",
        static_cast<Section& (Relocation::*)(void)>(&Relocation::section),
        "" RST_CLASS_REF(lief.ELF.Section) " to which the relocation applies",
        py::return_value_policy::reference)

    .def_property_readonly("is_rela",
      static_cast<getter_t<bool>>(&Relocation::is_rela),
      "``True`` if the relocation uses the :attr:`~lief.ELF.Relocation.addend` proprety")

    .def_property_readonly("is_rel",
      static_cast<getter_t<bool>>(&Relocation::is_rel),
      "``True`` if the relocation doesn't use the :attr:`~lief.ELF.Relocation.addend` proprety")

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
          std::string str =  stream.str();
          return str;
        });
}
