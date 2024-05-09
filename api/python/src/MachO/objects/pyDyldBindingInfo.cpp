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

#include "LIEF/MachO/DyldBindingInfo.hpp"
#include "enums_wrapper.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<DyldBindingInfo>(nb::module_& m) {
  nb::class_<DyldBindingInfo, BindingInfo> cls(m, "DyldBindingInfo",
      R"delim(
      This class represents a symbol binding operation associated with
      the LC_DYLD_INFO bytecode.

      This class does not represent a structure that exists in the Mach-O format
      specifications but it provides a *view* on an entry of the Dyld binding opcodes.

      See also: :class:`~lief.MachO.BindingInfo`
      )delim"_doc);


  enum_<DyldBindingInfo::CLASS>(cls, "CLASS")
  #define PY_ENUM(x) to_string(x), x
    .value(PY_ENUM(DyldBindingInfo::CLASS::WEAK))
    .value(PY_ENUM(DyldBindingInfo::CLASS::LAZY))
    .value(PY_ENUM(DyldBindingInfo::CLASS::STANDARD))
    .value(PY_ENUM(DyldBindingInfo::CLASS::THREADED))
  #undef PY_ENUM
  ;

  enum_<DyldBindingInfo::TYPE>(cls, "TYPE")
  #define PY_ENUM(x) to_string(x), x
    .value(PY_ENUM(DyldBindingInfo::TYPE::POINTER))
    .value(PY_ENUM(DyldBindingInfo::TYPE::TEXT_ABSOLUTE32))
    .value(PY_ENUM(DyldBindingInfo::TYPE::TEXT_PCREL32))
  #undef PY_ENUM
  ;

  cls
    .def_prop_rw("binding_class",
        nb::overload_cast<>(&DyldBindingInfo::binding_class, nb::const_),
        nb::overload_cast<DyldBindingInfo::CLASS>(&DyldBindingInfo::binding_class),
        "" RST_CLASS_REF(lief.MachO.BINDING_CLASS) " of the binding"_doc)

    .def_prop_rw("binding_type",
        nb::overload_cast<>(&DyldBindingInfo::binding_type, nb::const_),
        nb::overload_cast<DyldBindingInfo::TYPE>(&DyldBindingInfo::binding_type),
        R"delim(
        :class:`~lief.MachO.BIND_TYPES` of the binding.

        Usually, it is :attr:`~lief.MachO.BIND_TYPES.POINTER`.
        )delim"_doc)


    .def_prop_ro("original_offset", &DyldBindingInfo::original_offset,
        "Original relative offset of the binding opcodes"_doc)

    LIEF_DEFAULT_STR(DyldBindingInfo);

}

}
