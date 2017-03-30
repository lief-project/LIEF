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
#include "LIEF/Abstract/Section.hpp"
#include "LIEF/PE/Section.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (Section::*)(void) const;

template<class T>
using setter_t = void (Section::*)(T);

void init_PE_Section_class(py::module& m) {
  py::class_<Section, LIEF::Section>(m, "Section")
    .def(py::init<>())
    .def(py::init<const std::vector<uint8_t>&, const std::string&, uint32_t>())
    .def(py::init<const std::string&>())
    .def_property("virtual_size",
        static_cast<getter_t<uint32_t>>(&Section::virtual_size),
        static_cast<setter_t<uint32_t>>(&Section::virtual_size))

    .def_property("pointerto_relocation",
        static_cast<getter_t<uint32_t>>(&Section::pointerto_relocation),
        static_cast<setter_t<uint32_t>>(&Section::pointerto_relocation))

    .def_property("pointerto_line_numbers",
        static_cast<getter_t<uint32_t>>(&Section::pointerto_line_numbers),
        static_cast<setter_t<uint32_t>>(&Section::pointerto_line_numbers))

    .def_property("numberof_relocations",
        static_cast<getter_t<uint16_t>>(&Section::numberof_relocations),
        static_cast<setter_t<uint16_t>>(&Section::numberof_relocations))

    .def_property("numberof_line_numbers",
        static_cast<getter_t<uint16_t>>(&Section::numberof_line_numbers),
        static_cast<setter_t<uint16_t>>(&Section::numberof_line_numbers))

    .def_property("characteristics",
        static_cast<getter_t<uint32_t>>(&Section::characteristics),
        static_cast<setter_t<uint32_t>>(&Section::characteristics))

    .def_property_readonly("characteristics_lists",
        &Section::characteristics_list)

    .def("has_characteristic",
        &Section::has_characteristic)

    .def_property("data",
        static_cast<getter_t<std::vector<uint8_t>>>(&Section::content),
        static_cast<setter_t<const std::vector<uint8_t>&>>(&Section::content))


    .def("__eq__", &Section::operator==)
    .def("__ne__", &Section::operator!=)
    .def("__hash__",
        [] (const Section& section) {
          return LIEF::Hash::hash(section);
        })

    .def("__str__",
        [] (const Section& section) {
          std::ostringstream stream;
          stream << section;
          std::string str =  stream.str();
          return str;
        });


}
