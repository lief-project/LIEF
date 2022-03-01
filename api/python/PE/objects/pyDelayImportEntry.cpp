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

#include <string>
#include <sstream>

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/DelayImportEntry.hpp"

#include "pyPE.hpp"

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (DelayImportEntry::*)() const;

template<class T>
using setter_t = void (DelayImportEntry::*)(T);


template<>
void create<DelayImportEntry>(py::module& m) {
  py::class_<DelayImportEntry, LIEF::Symbol>(m, "DelayImportEntry",
      R"delim(
      Class that represents an entry (i.e. a delay import) in the delay import table (:class:`~lief.PE.DelayImport`).

      It extends the :class:`lief.Symbol` generic class that provides the :attr:`lief.Symbol.name`
      and :attr:`lief.Symbol.value`

      The meaning of :attr:`lief.Symbol.value` for this PE object is the address (as an RVA) in the IAT
      where the resolution should take place
      )delim")
    .def(py::init<>())

    .def_property("name",
        [] (const DelayImportEntry& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&DelayImportEntry::name),
        "Delay import name if not ordinal")

    .def_property("data",
        static_cast<getter_t<uint64_t>>(&DelayImportEntry::data),
        static_cast<setter_t<uint64_t>>(&DelayImportEntry::data),
        "Raw value")

    .def_property_readonly("is_ordinal",
        &DelayImportEntry::is_ordinal,
        "``True`` if it is an import by ordinal")

    .def_property_readonly("ordinal",
        &DelayImportEntry::ordinal,
        "Ordinal value (if any). See: :attr:`~lief.PE.DelayImportEntry.is_ordinal`")

    .def_property_readonly("hint",
        &DelayImportEntry::hint,
        "Index into the :attr:`lief.PE.Export.entries` that is used to speed-up the symbol resolution")

    .def_property_readonly("iat_value",
        &DelayImportEntry::iat_value,
        R"delim(
        Value of the current entry in the delay-loaded import address table.
        See: :attr:`~DelayImportEntry.iat`
        )delim")

    .def("__eq__", &DelayImportEntry::operator==)
    .def("__ne__", &DelayImportEntry::operator!=)
    .def("__hash__",
        [] (const DelayImportEntry& import_entry) {
          return Hash::hash(import_entry);
        })

    .def("__str__", [] (const DelayImportEntry& importEntry) {
          std::ostringstream stream;
          stream << importEntry;
          return stream.str();
        });
}
}
}
