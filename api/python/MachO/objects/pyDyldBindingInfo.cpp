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
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/DyldBindingInfo.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (DyldBindingInfo::*)() const;

template<class T>
using setter_t = void (DyldBindingInfo::*)(T);


template<>
void create<DyldBindingInfo>(py::module& m) {

  py::class_<DyldBindingInfo, BindingInfo>(m, "DyldBindingInfo",
      R"delim(
      This class represents a symbol binding operation associated with
      the LC_DYLD_INFO bytecode.

      This class does not represent a structure that exists in the Mach-O format
      specifications but it provides a *view* on an entry of the Dyld binding opcodes.

      See also: :class:`~lief.MachO.BindingInfo`
      )delim")

    .def_property("binding_class",
        static_cast<getter_t<BINDING_CLASS>>(&DyldBindingInfo::binding_class),
        static_cast<setter_t<BINDING_CLASS>>(&DyldBindingInfo::binding_class),
        "" RST_CLASS_REF(lief.MachO.BINDING_CLASS) " of the binding")

    .def_property("binding_type",
        static_cast<getter_t<BIND_TYPES>>(&DyldBindingInfo::binding_type),
        static_cast<setter_t<BIND_TYPES>>(&DyldBindingInfo::binding_type),
        R"delim(
        :class:`~lief.MachO.BIND_TYPES` of the binding.

        Usually, it is :attr:`~lief.MachO.BIND_TYPES.POINTER`.
        )delim")


    .def_property_readonly("original_offset",
        &DyldBindingInfo::original_offset,
        "Original relative offset of the binding opcodes")

    .def("__eq__", &DyldBindingInfo::operator==)
    .def("__ne__", &DyldBindingInfo::operator!=)
    .def("__hash__",
        [] (const DyldBindingInfo& info) {
          return Hash::hash(info);
        })

    .def("__str__",
        [] (const DyldBindingInfo& info) {
          std::ostringstream stream;
          std::string str = stream.str();
          return stream.str();
        });

}

}
}
