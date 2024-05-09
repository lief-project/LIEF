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

#include "LIEF/PE/ImportEntry.hpp"

#include "PE/pyPE.hpp"
#include "pySafeString.hpp"

namespace LIEF::PE::py {

template<>
void create<ImportEntry>(nb::module_& m) {
  nb::class_<ImportEntry, LIEF::Symbol>(m, "ImportEntry",
      R"delim(
      Class that represents an entry (i.e. an import) in the import table (:class:`~lief.PE.Import`).

      It extends the :class:`lief.Symbol` generic class that provides the :attr:`lief.Symbol.name`
      and :attr:`lief.Symbol.value`
      )delim"_doc)
    .def(nb::init<>())

    .def(nb::init<const std::string&>(),
        "Constructor from a :attr:`~lief.PE.ImportEntry.name`"_doc,
        "import_name"_a)

    .def(nb::init<uint64_t, const std::string&>(),
        "Constructor from a :attr:`~lief.PE.ImportEntry.data` and an optionally :attr:`~lief.PE.ImportEntry.name`"_doc,
        "data"_a, "name"_a = "")

    .def(nb::init<uint64_t, PE_TYPE, const std::string&>(),
        "Constructor from a :attr:`~lief.PE.ImportEntry.data`, a :attr:`~lief.PE.ImportEntry.type` and an optional :attr:`~lief.PE.ImportEntry.name`"_doc,
        "data"_a, "type"_a, "name"_a = "")

    .def(nb::init<const std::string&, PE_TYPE>(),
        "Constructor from a :attr:`~lief.PE.ImportEntry.name`, and a :attr:`~lief.PE.ImportEntry.type`"_doc,
        "name"_a, "type"_a)

    .def_prop_rw("name",
        [] (const ImportEntry& obj) {
          return LIEF::py::safe_string(obj.name());
        },
        nb::overload_cast<std::string>(&ImportEntry::name),
        "Import name if not ordinal"_doc)

    .def_prop_rw("data",
        nb::overload_cast<>(&ImportEntry::data, nb::const_),
        nb::overload_cast<uint64_t>(&ImportEntry::data),
        "Raw value"_doc)

    .def_prop_ro("is_ordinal",
        &ImportEntry::is_ordinal,
        "``True`` if it is an import by ordinal"_doc)

    .def_prop_ro("ordinal",
        &ImportEntry::ordinal,
        "Ordinal value (if any). See: :attr:`~lief.PE.ImportEntry.is_ordinal`"_doc)

    .def_prop_ro("hint",
        &ImportEntry::hint,
        "Index into the :attr:`lief.PE.Export.entries` that is used to speed-up the symbol resolution"_doc)

    .def_prop_ro("iat_value",
        &ImportEntry::iat_value,
        "Value of the current entry in the Import Address Table. It should match the lookup table value."_doc)

    .def_prop_ro("iat_address",
        &ImportEntry::iat_address,
        "**Original** address of the entry in the Import Address Table"_doc)

    LIEF_COPYABLE(ImportEntry)
    LIEF_DEFAULT_STR(ImportEntry);
}
}
