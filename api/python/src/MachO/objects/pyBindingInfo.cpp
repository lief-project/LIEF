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

#include "LIEF/MachO/BindingInfo.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/DylibCommand.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<BindingInfo>(nb::module_& m) {
  nb::class_<BindingInfo, LIEF::Object>(m, "BindingInfo",
      R"delim(
      Class that provides an interface over an entry in DyldInfo structure

      This class does not represent a structure that exists in the Mach-O format
      specifications but it provides a *view* of a binding operation that is performed
      by the Dyld binding bytecode (`LC_DYLD_INFO`) or the Dyld chained fixups (`DYLD_CHAINED_FIXUPS`)

      See: :class:`~lief.MachO.ChainedBindingInfo`, :class:`~lief.MachO.DyldBindingInfo`
      )delim"_doc)


    .def_prop_rw("address",
        nb::overload_cast<>(&BindingInfo::address, nb::const_),
        nb::overload_cast<uint64_t>(&BindingInfo::address),
        "Binding's address"_doc)

    .def_prop_rw("library_ordinal",
        nb::overload_cast<>(&BindingInfo::library_ordinal, nb::const_),
        nb::overload_cast<int32_t>(&BindingInfo::library_ordinal))

    .def_prop_rw("addend",
        nb::overload_cast<>(&BindingInfo::addend, nb::const_),
        nb::overload_cast<int64_t>(&BindingInfo::addend),
        "Value added to the segment's virtual address when binding"_doc)

    .def_prop_rw("weak_import",
        nb::overload_cast<>(&BindingInfo::is_weak_import, nb::const_),
        nb::overload_cast<bool>(&BindingInfo::set_weak_import))

    .def_prop_ro("has_library",
        &BindingInfo::has_library,
        "``True`` if the binding info has a " RST_CLASS_REF(lief.MachO.DylibCommand) " associated with"_doc)

    .def_prop_ro("library",
        nb::overload_cast<>(&BindingInfo::library),
        "" RST_CLASS_REF(lief.MachO.DylibCommand) " associated with the binding if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_segment",
        &BindingInfo::has_segment,
        "``True`` if the binding info has a " RST_CLASS_REF(lief.MachO.SegmentCommand) " associated with"_doc)

    .def_prop_ro("segment",
        nb::overload_cast<>(&BindingInfo::segment),
        "" RST_CLASS_REF(lief.MachO.SegmentCommand) " associated with the binding if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_symbol",
        &BindingInfo::has_symbol,
        "``True`` if the binding info has a " RST_CLASS_REF(lief.MachO.Symbol) " associated with"_doc)

    .def_prop_ro("symbol",
        nb::overload_cast<>(&BindingInfo::symbol),
        "" RST_CLASS_REF(lief.MachO.Symbol) " associated with the binding if any, or None"_doc,
        nb::rv_policy::reference_internal)


    LIEF_DEFAULT_STR(BindingInfo);

}

}
