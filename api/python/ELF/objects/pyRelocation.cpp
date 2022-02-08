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
#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/Section.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (Relocation::*)(void) const;

template<class T>
using setter_t = void (Relocation::*)(T);


template<>
void create<Relocation>(py::module& m) {

  // Relocation object
  py::class_<Relocation, LIEF::Relocation>(m, "Relocation",
      R"delim(
      Class that represents an ELF relocation.
      )delim")
    .def(py::init<>())
    .def(py::init<ARCH>(), "arch"_a)
    .def(py::init<uint64_t, uint32_t, int64_t, bool>(),
        "address"_a, "type"_a = 0, "addend"_a = 0, "is_rela"_a = false)

    .def_property("addend",
        static_cast<getter_t<int64_t>>(&Relocation::addend),
        static_cast<setter_t<int64_t>>(&Relocation::addend),
        "Additional value")

    .def_property("info",
        static_cast<getter_t<uint32_t>>(&Relocation::info),
        static_cast<setter_t<uint32_t>>(&Relocation::info),
        "Extra information like the symbol index")

    .def_property("purpose",
        static_cast<getter_t<RELOCATION_PURPOSES>>(&Relocation::purpose),
        static_cast<setter_t<RELOCATION_PURPOSES>>(&Relocation::purpose),
        R"delim(
        Purpose of the relocation (:class:`~lief.ELF.RELOCATION_PURPOSES`).

        This value provides the information about how the relocation is used (PLT/GOT resolution, ``.o`` file, ...)
        )delim")

    .def_property("type",
        static_cast<getter_t<uint32_t>>(&Relocation::type),
        static_cast<setter_t<uint32_t>>(&Relocation::type),
        R"delim(
        Relocation type. This value depends on the underlying architecture.

        See:
          * :class:`~lief.ELF.RELOCATION_X86_64`
          * :class:`~lief.ELF.RELOCATION_i386`
          * :class:`~lief.ELF.RELOCATION_AARCH64`
          * :class:`~lief.ELF.RELOCATION_ARM`
        )delim")

    .def_property_readonly("has_symbol",
        &Relocation::has_symbol,
        "``True`` if a " RST_CLASS_REF(lief.ELF.Symbol) " is associated with the relocation")

    .def_property("symbol",
        static_cast<Symbol* (Relocation::*)(void)>(&Relocation::symbol),
        static_cast<void (Relocation::*)(Symbol*)>(&Relocation::symbol),
        R"delim(
        :class:`~lief.ELF.Symbol` associated with the relocation or None
        if no symbol are associated with this relocation.
        )delim",
        py::return_value_policy::reference)

    .def_property_readonly("has_section",
        &Relocation::has_section,
        R"delim(
        ``True`` if this relocation has a :class:`lief.ELF.Section` associated with.

        This is usually the case for object files (``.o``)
        )delim")

    .def_property_readonly("section",
        static_cast<Section* (Relocation::*)(void)>(&Relocation::section),
        R"delim(
        :class:`~lief.ELF.Section` in which the relocation is applied or None if not relevant
        )delim",
        py::return_value_policy::reference)

    .def_property_readonly("is_rela",
      static_cast<getter_t<bool>>(&Relocation::is_rela),
      "``True`` if the relocation **uses** the :attr:`~lief.ELF.Relocation.addend` proprety")

    .def_property_readonly("is_rel",
      static_cast<getter_t<bool>>(&Relocation::is_rel),
      "``True`` if the relocation **doesn't use** the :attr:`~lief.ELF.Relocation.addend` proprety")

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

}
}
