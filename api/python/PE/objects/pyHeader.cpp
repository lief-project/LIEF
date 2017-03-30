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

#include "LIEF/visitors/Hash.hpp"
#include "LIEF/PE/Header.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (Header::*)(void) const;

template<class T>
using setter_t = void (Header::*)(T);

void init_PE_Header_class(py::module& m) {
  py::class_<Header>(m, "Header")
    .def(py::init<>())

    .def_property("signature",
        static_cast<getter_t<const Header::signature_t&>>(&Header::signature),
        static_cast<setter_t<const Header::signature_t&>>(&Header::signature))

    .def_property("machine",
        static_cast<getter_t<MACHINE_TYPES>>(&Header::machine),
        static_cast<setter_t<MACHINE_TYPES>>(&Header::machine))

    .def_property("numberof_sections",
        static_cast<getter_t<uint16_t>>(&Header::numberof_sections),
        static_cast<setter_t<uint16_t>>(&Header::numberof_sections),
        "Number of sections in the binary")

    .def_property("time_date_stamps",
        static_cast<getter_t<uint32_t>>(&Header::time_date_stamp),
        static_cast<setter_t<uint32_t>>(&Header::time_date_stamp))

    .def_property("pointerto_symbol_table",
        static_cast<getter_t<uint32_t>>(&Header::pointerto_symbol_table),
        static_cast<setter_t<uint32_t>>(&Header::pointerto_symbol_table))

    .def_property("numberof_symbols",
        static_cast<getter_t<uint32_t>>(&Header::numberof_symbols),
        static_cast<setter_t<uint32_t>>(&Header::numberof_symbols))

    .def_property("sizeof_optional_header",
        static_cast<getter_t<uint16_t>>(&Header::sizeof_optional_header),
        static_cast<setter_t<uint16_t>>(&Header::sizeof_optional_header))

    .def_property("characteristics",
        static_cast<getter_t<uint16_t>>(&Header::characteristics),
        static_cast<getter_t<uint16_t>>(&Header::characteristics))

    .def("has_characteristic",
        &Header::has_characteristic)

    .def("add_characteristic",
        &Header::add_characteristic)

    .def("remove_characteristic",
        &Header::remove_characteristic)

    .def_property_readonly("characteristics_list",
        &Header::characteristics_list)


    .def("__eq__", &Header::operator==)
    .def("__ne__", &Header::operator!=)
    .def("__hash__",
        [] (const Header& header) {
          return LIEF::Hash::hash(header);
        })


    .def("__str__", [] (const Header& header)
        {
          std::ostringstream stream;
          stream << header;
          std::string str = stream.str();
          return str;
        });


}
