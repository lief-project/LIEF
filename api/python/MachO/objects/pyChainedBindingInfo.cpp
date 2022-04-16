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
#include "LIEF/MachO/ChainedBindingInfo.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<>
void create<ChainedBindingInfo>(py::module& m) {

  py::class_<ChainedBindingInfo, BindingInfo>(m, "ChainedBindingInfo",
      R"delim(
      This class represents a symbol binding operation associated with
      the LC_DYLD_CHAINED_FIXUPS command.

      This class does not represent a structure that exists in the Mach-O format
      specifications but it provides a *view* on an entry.

      See also: :class:`~lief.MachO.BindingInfo`
      )delim")

    .def_property_readonly("format",
                           &ChainedBindingInfo::format,
                           R"delim(
                           :class:`~lief.MachO.DYLD_CHAINED_FORMAT` of the import
                           )delim")

    .def_property_readonly("ptr_format",
                           &ChainedBindingInfo::ptr_format,
                           R"delim(
                           :class:`~lief.MachO.DYLD_CHAINED_PTR_FORMAT` of the import
                           )delim")

    .def_property("offset",
                  py::overload_cast<>(&ChainedBindingInfo::offset, py::const_),
                  py::overload_cast<uint32_t>(&ChainedBindingInfo::offset),
                  R"delim(
                  Offset of the entry in the chained fixups
                  )delim")

    .def_property_readonly("sign_extended_addend", &ChainedBindingInfo::sign_extended_addend)

    .def("__eq__", &ChainedBindingInfo::operator==)
    .def("__ne__", &ChainedBindingInfo::operator!=)
    .def("__hash__",
        [] (const ChainedBindingInfo& info) {
          return Hash::hash(info);
        })

    .def("__str__",
        [] (const ChainedBindingInfo& info) {
          std::ostringstream stream;
          std::string str = stream.str();
          return stream.str();
        });

}

}
}
