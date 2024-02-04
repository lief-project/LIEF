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
#include "PE/pyPE.hpp"
#include "pyIterator.hpp"
#include "pySafeString.hpp"

#include "LIEF/PE/DelayImport.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<DelayImport>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<DelayImport, LIEF::Object> imp(m, "DelayImport",
      R"delim(
      Class that represents a PE delay import
      )delim"_doc);

  init_ref_iterator<DelayImport::it_entries>(imp, "it_entries");

  imp
    .def(nb::init<const std::string&>(),
        "Constructor from a library name"_doc,
        "library_name"_a)

    .def_prop_ro("entries",
        nb::overload_cast<>(&DelayImport::entries),
        "Iterator over the " RST_CLASS_REF(lief.PE.DelayImportEntry) " (functions)"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_rw("name",
        [] (const DelayImport& obj) {
          return safe_string(obj.name());
        },
        nb::overload_cast<std::string>(&DelayImport::name),
        "Library name (e.g. ``kernel32.dll``)"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("attribute",
        nb::overload_cast<>(&DelayImport::attribute, nb::const_),
        nb::overload_cast<uint32_t>(&DelayImport::attribute),
        R"delim(
        Reserved and **should** be zero according to the PE specifications
        )delim"_doc)

    .def_prop_rw("handle",
        nb::overload_cast<>(&DelayImport::handle, nb::const_),
        nb::overload_cast<uint32_t>(&DelayImport::handle),
        R"delim(
        The RVA of the module handle (in the ``.data`` section)
        It is used for storage by the routine that is supplied to manage delay-loading.
        )delim"_doc)

    .def_prop_rw("iat",
        nb::overload_cast<>(&DelayImport::iat, nb::const_),
        nb::overload_cast<uint32_t>(&DelayImport::iat),
        R"delim(
        RVA of the delay-load import address table.
        )delim"_doc)

    .def_prop_rw("names_table",
        nb::overload_cast<>(&DelayImport::names_table, nb::const_),
        nb::overload_cast<uint32_t>(&DelayImport::names_table),
        R"delim(
        RVA of the delay-load import names table.
        The content of this table has the layout as the Import lookup table
        )delim"_doc)

    .def_prop_rw("biat",
        nb::overload_cast<>(&DelayImport::biat, nb::const_),
        nb::overload_cast<uint32_t>(&DelayImport::biat),
        R"delim(
        RVA of the **bound** delay-load import address table or 0
        if the table does not exist.
        )delim"_doc)


    .def_prop_rw("uiat",
        nb::overload_cast<>(&DelayImport::uiat, nb::const_),
        nb::overload_cast<uint32_t>(&DelayImport::uiat),
        R"delim(
        RVA of the **unload** delay-load import address table or 0
        if the table does not exist.

        According to the PE specifications, this table is an
        exact copy of the delay import address table that can be
        used to to restore the original IAT the case of unloading.
        )delim"_doc)

    .def_prop_rw("timestamp",
        nb::overload_cast<>(&DelayImport::timestamp, nb::const_),
        nb::overload_cast<uint32_t>(&DelayImport::timestamp),
        R"delim(
        The timestamp of the DLL to which this image has been bound.
        )delim"_doc)

    LIEF_COPYABLE(DelayImport)
    LIEF_DEFAULT_STR(DelayImport);
}
}
