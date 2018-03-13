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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/Export.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (Export::*)(void) const;

template<class T>
using setter_t = void (Export::*)(T);

template<class T>
using no_const_getter = T (Export::*)(void);

void init_PE_Export_class(py::module& m) {
  py::class_<Export, LIEF::Object>(m, "Export")
    .def(py::init<>())

    .def_property("name",
        [] (const Export& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&Export::name))

    .def_property("export_flags",
        static_cast<getter_t<uint32_t>>(&Export::export_flags),
        static_cast<setter_t<uint32_t>>(&Export::export_flags))

    .def_property("timestamp",
        static_cast<getter_t<uint32_t>>(&Export::timestamp),
        static_cast<setter_t<uint32_t>>(&Export::timestamp))

    .def_property("major_version",
        static_cast<getter_t<uint16_t>>(&Export::major_version),
        static_cast<setter_t<uint16_t>>(&Export::major_version))

    .def_property("minor_version",
        static_cast<getter_t<uint16_t>>(&Export::minor_version),
        static_cast<setter_t<uint16_t>>(&Export::minor_version))

    .def_property("ordinal_base",
        static_cast<getter_t<uint32_t>>(&Export::ordinal_base),
        static_cast<setter_t<uint32_t>>(&Export::ordinal_base))

    .def_property_readonly("entries",
        static_cast<no_const_getter<it_export_entries>>(&Export::entries),
        py::return_value_policy::reference_internal)


    .def("__eq__", &Export::operator==)
    .def("__ne__", &Export::operator!=)
    .def("__hash__",
        [] (const Export& export_) {
          return Hash::hash(export_);
        })

    .def("__str__", [] (const Export& export_)
        {
          std::ostringstream stream;
          stream << export_;
          std::string str = stream.str();
          return str;
        });


}
