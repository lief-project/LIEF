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
#include "LIEF/PE/ImportEntry.hpp"

#include "pyPE.hpp"

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (ImportEntry::*)(void) const;

template<class T>
using setter_t = void (ImportEntry::*)(T);


template<>
void create<ImportEntry>(py::module& m) {
  py::class_<ImportEntry, LIEF::Symbol>(m, "ImportEntry",
      R"delim(
      Class that represents an entry (i.e. an import) in the import table (:class:`~lief.PE.Import`).

      It extends the :class:`lief.Symbol` generic class that provides the :attr:`lief.Symbol.name`
      and :attr:`lief.Symbol.value`
      )delim")
    .def(py::init<>())

    .def(py::init<const std::string&>(),
        "Constructor from a :attr:`~lief.PE.ImportEntry.name`",
        "import_name"_a)

    .def(py::init<uint64_t, const std::string&>(),
        "Constructor from a :attr:`~lief.PE.ImportEntry.data` and an optionally :attr:`~lief.PE.ImportEntry.name`",
        "data"_a, "name"_a = "")

    .def_property("name",
        [] (const ImportEntry& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&ImportEntry::name),
        "Import name if not ordinal")

    .def_property("data",
        static_cast<getter_t<uint64_t>>(&ImportEntry::data),
        static_cast<setter_t<uint64_t>>(&ImportEntry::data),
        "Raw value")

    .def_property_readonly("is_ordinal",
        &ImportEntry::is_ordinal,
        "``True`` if it is an import by ordinal")

    .def_property_readonly("ordinal",
        &ImportEntry::ordinal,
        "Ordinal value (if any). See: :attr:`~lief.PE.ImportEntry.is_ordinal`")

    .def_property_readonly("hint",
        &ImportEntry::hint,
        "Index into the :attr:`lief.PE.Export.entries` that is used to speed-up the symbol resolution")

    .def_property_readonly("iat_value",
        &ImportEntry::iat_value,
        "Value of the current entry in the Import Address Table. It should match the lookup table value.")

    .def_property_readonly("iat_address",
        &ImportEntry::iat_address,
        "**Original** address of the entry in the Import Address Table")


    .def("__eq__", &ImportEntry::operator==)
    .def("__ne__", &ImportEntry::operator!=)
    .def("__hash__",
        [] (const ImportEntry& import_entry) {
          return Hash::hash(import_entry);
        })

    .def("__str__", [] (const ImportEntry& importEntry)
        {
          std::ostringstream stream;
          stream << importEntry;
          std::string str = stream.str();
          return str;
        });
}
}
}
