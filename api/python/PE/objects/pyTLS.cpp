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
#include "LIEF/PE/TLS.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (TLS::*)(void) const;

template<class T>
using setter_t = void (TLS::*)(T);

template<class T>
using no_const_getter = T (TLS::*)(void);


template<>
void create<TLS>(py::module& m) {
  py::class_<TLS, LIEF::Object>(m, "TLS",
      R"delim(
      Class which represents the PE Thread Local Storage.
      This PE structure is also used to implement binary/library constructors.
      )delim")
    .def(py::init<>(),
        "Default constructor")

    .def_property("callbacks",
        static_cast<getter_t<const std::vector<uint64_t>&>>(&TLS::callbacks),
        static_cast<setter_t<const std::vector<uint64_t>&>>(&TLS::callbacks),
        R"delim(
        List of the callback associated with the current TLS.

        These functions are called before any other functions of the PE binary.
        )delim")

    .def_property("addressof_index",
        static_cast<getter_t<uint64_t>>(&TLS::addressof_index),
        static_cast<setter_t<uint64_t>>(&TLS::addressof_index),
        R"delim(
        The location to receive the TLS index, which the loader assigns.
        This location is in an ordinary data section, so it can be given a symbolic name that is accessible
        to the program.
        )delim")

    .def_property("addressof_callbacks",
        static_cast<getter_t<uint64_t>>(&TLS::addressof_callbacks),
        static_cast<setter_t<uint64_t>>(&TLS::addressof_callbacks),
        R"delim(
        The pointer to an array of TLS callback functions.

        The array is null-terminated, so if no callback function
        is supported, this field points to 4 bytes set to zero.

        See: :attr:`~lief.PE.TLS.callbacks`
        )delim")

    .def_property("sizeof_zero_fill",
        static_cast<getter_t<uint32_t>>(&TLS::sizeof_zero_fill),
        static_cast<setter_t<uint32_t>>(&TLS::sizeof_zero_fill),
        R"delim(
        The size in bytes of the template, beyond the initialized data delimited by
        the :attr:`~lief.PE.TLS.addressof_raw_data` fields.
        The total template size should be the same as the total size of TLS data in the image file.
        The zero fill is the amount of data that comes after the initialized nonzero data.
        )delim")


    .def_property("characteristics",
        static_cast<getter_t<uint32_t>>(&TLS::characteristics),
        static_cast<setter_t<uint32_t>>(&TLS::characteristics),
        R"delim(
        The four bits [23:20] describe alignment info.
        Possible values are those defined as IMAGE_SCN_ALIGN_*, which are also used to
        describe alignment of section in object files. The other 28 bits are reserved for future use.
        )delim")

    .def_property("addressof_raw_data",
        static_cast<getter_t<std::pair<uint64_t, uint64_t>>>(&TLS::addressof_raw_data),
        static_cast<setter_t<std::pair<uint64_t, uint64_t>>>(&TLS::addressof_raw_data),
        R"delim(
        Tuple ``(start address, end address)`` of the TLS template.
        The template is a block of data that is used to initialize TLS data.
        The system copies all of this data each time a thread is created, so it must not be
        corrupted.

        .. note::

          These addresses are not RVA. It is addresses for which there should be a base
          relocation in the ``.reloc`` section.
        )delim")

    .def_property("data_template",
        static_cast<getter_t<const std::vector<uint8_t>&>>(&TLS::data_template),
        static_cast<setter_t<const std::vector<uint8_t>&>>(&TLS::data_template),
        "The data template content")

    .def_property_readonly("has_section",
        &TLS::has_section,
        "``True`` if there is a " RST_CLASS_REF(lief.PE.Section) " associated with the TLS object")

    .def_property_readonly("has_data_directory",
        &TLS::has_data_directory,
        "``True`` if there is a " RST_CLASS_REF(lief.PE.DataDirectory) " associated with the TLS object")

    .def_property_readonly("directory",
        static_cast<no_const_getter<DataDirectory*>>(&TLS::directory),
        "" RST_CLASS_REF(lief.PE.DataDirectory) " associated with the TLS object (or None if not linked)",
        py::return_value_policy::reference)

    .def_property_readonly("section",
        static_cast<no_const_getter<Section*>>(&TLS::section),
        "" RST_CLASS_REF(lief.PE.Section) " associated with the TLS object (or None if not linked)",
        py::return_value_policy::reference)


    .def("__eq__", &TLS::operator==)
    .def("__ne__", &TLS::operator!=)
    .def("__hash__",
        [] (const TLS& tls) {
          return Hash::hash(tls);
        })

    .def("__str__", [] (const TLS& tls)
        {
          std::ostringstream stream;
          stream << tls;
          std::string str = stream.str();
          return str;
        });
}

}
}
