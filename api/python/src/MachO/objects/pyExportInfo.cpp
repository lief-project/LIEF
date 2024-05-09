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
#include <nanobind/stl/vector.h>

#include "LIEF/MachO/ExportInfo.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/DylibCommand.hpp"

#include "MachO/pyMachO.hpp"
#include "pyIterator.hpp"
#include "enums_wrapper.hpp"

namespace LIEF::MachO::py {

template<>
void create<ExportInfo>(nb::module_& m) {
  nb::class_<ExportInfo, Object> cls(m, "ExportInfo",
      R"delim(
      Class that provides an interface over the Dyld export info

      This class does not represent a structure that exists in the Mach-O format
      specification but provides a *view* on an entry of the Dyld export trie.
      )delim"_doc);

  enum_<ExportInfo::KIND>(cls, "KIND")
  #define PY_ENUM(x) to_string(x), x
    .value(PY_ENUM(ExportInfo::KIND::REGULAR))
    .value(PY_ENUM(ExportInfo::KIND::THREAD_LOCAL_KIND))
    .value(PY_ENUM(ExportInfo::KIND::ABSOLUTE_KIND))
  #undef PY_ENUM
  ;

  enum_<ExportInfo::FLAGS>(cls, "FLAGS", nb::is_arithmetic())
  #define PY_ENUM(x) to_string(x), x
    .value(PY_ENUM(ExportInfo::FLAGS::WEAK_DEFINITION))
    .value(PY_ENUM(ExportInfo::FLAGS::REEXPORT))
    .value(PY_ENUM(ExportInfo::FLAGS::STUB_AND_RESOLVER))
  #undef PY_ENUM
  ;

  cls
    .def_prop_ro("node_offset",
        nb::overload_cast<>(&ExportInfo::node_offset, nb::const_),
        "Original offset in the export Trie"_doc)

    .def_prop_ro("kind",
        nb::overload_cast<>(&ExportInfo::kind, nb::const_),
        "The export's kind: regular, thread local, absolute, ... (" RST_CLASS_REF(lief.MachO.ExportInfo.KIND) ")"_doc)

    .def_prop_ro("flags_list",
        nb::overload_cast<>(&ExportInfo::flags_list, nb::const_),
        "Return flags as a list of " RST_CLASS_REF(lief.MachO.ExportInfo.FLAGS) ""_doc)

    .def_prop_rw("flags",
        nb::overload_cast<>(&ExportInfo::flags, nb::const_),
        nb::overload_cast<uint64_t>(&ExportInfo::flags),
        "Some information (" RST_CLASS_REF(lief.MachO.ExportInfo.FLAGS) ") about the export (like weak export, reexport, ...)"_doc)

    .def_prop_rw("address",
        nb::overload_cast<>(&ExportInfo::address, nb::const_),
        nb::overload_cast<uint64_t>(&ExportInfo::address),
        "The address of the export"_doc)

    .def_prop_ro("alias",
        nb::overload_cast<>(&ExportInfo::alias, nb::const_),
        "" RST_CLASS_REF(lief.MachO.Symbol) " alias if the current symbol is re-exported"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("alias_library",
        nb::overload_cast<>(&ExportInfo::alias_library, nb::const_),
        "If the current symbol has an alias, it returns the " RST_CLASS_REF(lief.MachO.DylibCommand) " "
        " command associated with"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_symbol",
        &ExportInfo::has_symbol,
        "``True`` if the export info has a " RST_CLASS_REF(lief.MachO.Symbol) " associated with"_doc)

    .def("has",
        &ExportInfo::has,
        "Check if the flag " RST_CLASS_REF(lief.MachO.ExportInfo.FLAGS) " given in first parameter is present"_doc,
        "flag"_a)

    .def_prop_ro("symbol",
        nb::overload_cast<>(&ExportInfo::symbol),
        "" RST_CLASS_REF(lief.MachO.Symbol) " associated with the export if any, or None "_doc,
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(ExportInfo);
}

}
