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

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/BindingInfo.hpp"

#include "pyMachO.hpp"

template<class T>
using getter_t = T (BindingInfo::*)(void) const;

template<class T>
using setter_t = void (BindingInfo::*)(T);


void init_MachO_BindingInfo_class(py::module& m) {

  py::class_<BindingInfo, LIEF::Object>(m, "BindingInfo")

    .def_property("binding_class",
        static_cast<getter_t<BINDING_CLASS>>(&BindingInfo::binding_class),
        static_cast<setter_t<BINDING_CLASS>>(&BindingInfo::binding_class),
        "" RST_CLASS_REF(lief.MachO.BINDING_CLASS) " of the binding",
        py::return_value_policy::reference_internal)

    .def_property("address",
        static_cast<getter_t<uint64_t>>(&BindingInfo::address),
        static_cast<setter_t<uint64_t>>(&BindingInfo::address),
        "Binding's address",
        py::return_value_policy::reference_internal)

    .def_property("binding_type",
        static_cast<getter_t<BIND_TYPES>>(&BindingInfo::binding_type),
        static_cast<setter_t<BIND_TYPES>>(&BindingInfo::binding_type),
        "" RST_CLASS_REF(lief.MachO.BIND_TYPES) " of the binding\n"
        "Most of the times it's :attr:`~lief.MachO.BIND_TYPES.POINTER`",
        py::return_value_policy::reference_internal)


    .def_property("library_ordinal",
        static_cast<getter_t<int32_t>>(&BindingInfo::library_ordinal),
        static_cast<setter_t<int32_t>>(&BindingInfo::library_ordinal),
        py::return_value_policy::reference_internal)

    .def_property("addend",
        static_cast<getter_t<int64_t>>(&BindingInfo::addend),
        static_cast<setter_t<int64_t>>(&BindingInfo::addend),
        "Value added to the segment's virtual address when binding",
        py::return_value_policy::reference_internal)

    .def_property("weak_import",
        static_cast<getter_t<bool>>(&BindingInfo::is_weak_import),
        static_cast<setter_t<bool>>(&BindingInfo::set_weak_import),
        py::return_value_policy::reference_internal)


    .def_property_readonly("has_library",
        &BindingInfo::has_library,
        "``True`` if the binding info has a " RST_CLASS_REF(lief.MachO.DylibCommand) " associated with")

    .def_property_readonly("library",
        static_cast<DylibCommand& (BindingInfo::*)(void)>(&BindingInfo::library),
        "" RST_CLASS_REF(lief.MachO.DylibCommand) " associated with the binding (if any)",
        py::return_value_policy::reference)


    .def_property_readonly("has_segment",
        &BindingInfo::has_segment,
        "``True`` if the binding info has a " RST_CLASS_REF(lief.MachO.SegmentCommand) " associated with")

    .def_property_readonly("segment",
        static_cast<SegmentCommand& (BindingInfo::*)(void)>(&BindingInfo::segment),
        "" RST_CLASS_REF(lief.MachO.SegmentCommand) " associated with the binding (if any)",
        py::return_value_policy::reference)


    .def_property_readonly("has_symbol",
        &BindingInfo::has_symbol,
        "``True`` if the binding info has a " RST_CLASS_REF(lief.MachO.Symbol) " associated with")

    .def_property_readonly("symbol",
        static_cast<Symbol& (BindingInfo::*)(void)>(&BindingInfo::symbol),
        "" RST_CLASS_REF(lief.MachO.Symbol) " associated with the binding (if any)",
        py::return_value_policy::reference)


    .def("__eq__", &BindingInfo::operator==)
    .def("__ne__", &BindingInfo::operator!=)
    .def("__hash__",
        [] (const BindingInfo& binding_info) {
          return Hash::hash(binding_info);
        })


    .def("__str__",
        [] (const BindingInfo& binding_info)
        {
          std::ostringstream stream;
          stream << binding_info;
          std::string str = stream.str();
          return str;
        });

}
