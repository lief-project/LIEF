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

#include "LIEF/PE/DelayImportEntry.hpp"

#include "PE/pyPE.hpp"
#include "pySafeString.hpp"

namespace LIEF::PE::py {

template<>
void create<DelayImportEntry>(nb::module_& m) {
  nb::class_<DelayImportEntry, LIEF::Symbol>(m, "DelayImportEntry",
      R"delim(
      Class that represents an entry (i.e. a delay import) in the delay import table (:class:`~lief.PE.DelayImport`).

      It extends the :class:`lief.Symbol` generic class that provides the :attr:`lief.Symbol.name`
      and :attr:`lief.Symbol.value`

      The meaning of :attr:`lief.Symbol.value` for this PE object is the address (as an RVA) in the IAT
      where the resolution should take place
      )delim"_doc)
    .def(nb::init<>())

    .def_prop_rw("name",
        [] (const DelayImportEntry& obj) {
          return LIEF::py::safe_string(obj.name());
        },
        nb::overload_cast<std::string>(&DelayImportEntry::name),
        "Delay import name if not ordinal"_doc)

    .def_prop_rw("data",
        nb::overload_cast<>(&DelayImportEntry::data, nb::const_),
        nb::overload_cast<uint64_t>(&DelayImportEntry::data),
        "Raw value"_doc)

    .def_prop_ro("is_ordinal",
        &DelayImportEntry::is_ordinal,
        "``True`` if it is an import by ordinal"_doc)

    .def_prop_ro("ordinal",
        &DelayImportEntry::ordinal,
        "Ordinal value (if any). See: :attr:`~lief.PE.DelayImportEntry.is_ordinal`"_doc)

    .def_prop_ro("hint",
        &DelayImportEntry::hint,
        "Index into the :attr:`lief.PE.Export.entries` that is used to speed-up the symbol resolution"_doc)

    .def_prop_ro("iat_value",
        &DelayImportEntry::iat_value,
        R"delim(
        Value of the current entry in the delay-loaded import address table.
        See: :attr:`~DelayImportEntry.iat`
        )delim"_doc)

    LIEF_COPYABLE(DelayImportEntry)
    LIEF_DEFAULT_STR(DelayImportEntry);

}
}
