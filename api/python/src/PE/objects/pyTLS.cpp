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
#include "PE/pyPE.hpp"

#include "nanobind/extra/memoryview.hpp"

#include "LIEF/PE/TLS.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/DataDirectory.hpp"

#include <string>
#include <sstream>

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/pair.h>

namespace LIEF::PE::py {

template<>
void create<TLS>(nb::module_& m) {
  nb::class_<TLS, LIEF::Object>(m, "TLS",
      R"delim(
      Class which represents the PE Thread Local Storage.
      This PE structure is also used to implement binary/library constructors.
      )delim"_doc)
    .def(nb::init<>(),
        "Default constructor"_doc)

    .def_prop_rw("callbacks",
        nb::overload_cast<>(&TLS::callbacks, nb::const_),
        nb::overload_cast<std::vector<uint64_t>>(&TLS::callbacks),
        R"delim(
        List of the callback associated with the current TLS.

        These functions are called before any other functions.
        )delim"_doc)

    .def_prop_rw("addressof_index",
        nb::overload_cast<>(&TLS::addressof_index, nb::const_),
        nb::overload_cast<uint64_t>(&TLS::addressof_index),
        R"delim(
        The location to receive the TLS index assigned by the loader.
        This location should be located in a writable section like ``.data``.
        )delim"_doc)

    .def_prop_rw("addressof_callbacks",
        nb::overload_cast<>(&TLS::addressof_callbacks, nb::const_),
        nb::overload_cast<uint64_t>(&TLS::addressof_callbacks),
        R"delim(
        Pointer to an array of TLS callback functions.

        The array is null-terminated, so if there is no callback,
        this field points to 4 bytes set to zero.

        See: :attr:`~lief.PE.TLS.callbacks`
        )delim"_doc)

    .def_prop_rw("sizeof_zero_fill",
        nb::overload_cast<>(&TLS::sizeof_zero_fill, nb::const_),
        nb::overload_cast<uint32_t>(&TLS::sizeof_zero_fill),
        R"delim(
        Size in bytes of the zeros to be *padded* after the data specified by
        :attr:`~.data_template`.
        )delim"_doc)


    .def_prop_rw("characteristics",
        nb::overload_cast<>(&TLS::characteristics, nb::const_),
        nb::overload_cast<uint32_t>(&TLS::characteristics),
        R"delim(
        The four bits [23:20] describe alignment info.
        Possible values are those defined as ``IMAGE_SCN_ALIGN_*``, which are
        also used to describe alignment of section in object files.
        The other 28 bits are reserved for future use.
        )delim"_doc)

    .def_prop_rw("addressof_raw_data",
        nb::overload_cast<>(&TLS::addressof_raw_data, nb::const_),
        nb::overload_cast<std::pair<uint64_t, uint64_t>>(&TLS::addressof_raw_data),
        R"delim(
        Tuple ``(start address, end address)`` of the TLS template.
        The template is a block of data that is used to initialize TLS data.
        The system copies all of this data each time a thread is created, so it
        must not be corrupted.

        .. note::

          These addresses are not RVA. It is addresses for which there should
          be a base relocation in the ``.reloc`` section.
        )delim"_doc)

    .def_prop_rw("data_template",
        [] (const TLS& self) {
          const span<const uint8_t> content = self.data_template();
          return nb::memoryview::from_memory(content.data(), content.size());
        },
        nb::overload_cast<std::vector<uint8_t>>(&TLS::data_template),
        "The initial content used to initialize TLS data."_doc)

    .def_prop_ro("has_section",
        &TLS::has_section,
        "``True`` if there is a " RST_CLASS_REF(lief.PE.Section) " associated with the TLS object"_doc)

    .def_prop_ro("has_data_directory",
        &TLS::has_data_directory,
        "``True`` if there is a " RST_CLASS_REF(lief.PE.DataDirectory) " associated with the TLS object"_doc)

    .def_prop_ro("directory",
        nb::overload_cast<>(&TLS::directory),
        "" RST_CLASS_REF(lief.PE.DataDirectory) " associated with the TLS object (or None if not linked)"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("section",
        nb::overload_cast<>(&TLS::section),
        "" RST_CLASS_REF(lief.PE.Section) " associated with the TLS object (or None if not linked)"_doc,
        nb::rv_policy::reference_internal)

    LIEF_COPYABLE(TLS)
    LIEF_DEFAULT_STR(TLS);
}
}
