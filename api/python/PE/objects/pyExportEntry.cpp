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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/ExportEntry.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (ExportEntry::*)(void) const;

template<class T>
using setter_t = void (ExportEntry::*)(T);


template<>
void create<ExportEntry>(py::module& m) {
  py::class_<ExportEntry, LIEF::Symbol> export_entry(m, "ExportEntry",
      R"delim(
      Class which represents a PE Export entry (cf. :class:`lief.PE.Export`)
      )delim");

  py::class_<ExportEntry::forward_information_t>(export_entry, "forward_information_t")
    .def_readwrite("library", &ExportEntry::forward_information_t::library)
    .def_readwrite("function", &ExportEntry::forward_information_t::function)

    .def("__str__", [] (const ExportEntry::forward_information_t& info)
        {
          std::ostringstream stream;
          stream << info;
          return  stream.str();
        });

  export_entry
    .def(py::init<>())

    .def_property("name",
        [] (const ExportEntry& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&ExportEntry::name))

    .def_property("ordinal",
        static_cast<getter_t<uint16_t>>(&ExportEntry::ordinal),
        static_cast<setter_t<uint16_t>>(&ExportEntry::ordinal))

    .def_property("address",
        static_cast<getter_t<uint32_t>>(&ExportEntry::address),
        static_cast<setter_t<uint32_t>>(&ExportEntry::address))

    .def_property("is_extern",
        static_cast<getter_t<bool>>(&ExportEntry::is_extern),
        static_cast<setter_t<bool>>(&ExportEntry::is_extern))

    .def_property_readonly("is_forwarded",
        &ExportEntry::is_forwarded)

    .def_property_readonly("forward_information",
        &ExportEntry::forward_information)

    .def_property_readonly("function_rva",
        &ExportEntry::function_rva)

    .def("__eq__", &ExportEntry::operator==)
    .def("__ne__", &ExportEntry::operator!=)
    .def("__hash__",
        [] (const ExportEntry& export_entry) {
          return Hash::hash(export_entry);
        })

    .def("__str__", [] (const ExportEntry& entry)
        {
          std::ostringstream stream;
          stream << entry;
          std::string str = stream.str();
          return str;
        });
}
}
}
