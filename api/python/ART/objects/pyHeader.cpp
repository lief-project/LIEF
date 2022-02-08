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
#include "LIEF/ART/Header.hpp"
#include "LIEF/ART/hash.hpp"

#include "pyART.hpp"

namespace LIEF {
namespace ART {

template<class T>
using getter_t = T (Header::*)(void) const;

template<class T>
using setter_t = void (Header::*)(T);

template<>
void create<Header>(py::module& m) {

  py::class_<Header, LIEF::Object>(m, "Header", "ART Header representation")
    .def_property_readonly("magic",
        static_cast<getter_t<Header::magic_t>>(&Header::magic)
    )
    .def_property_readonly("version",
        static_cast<getter_t<art_version_t>>(&Header::version)
    )
    .def_property_readonly("image_begin",
        static_cast<getter_t<uint32_t>>(&Header::image_begin)
    )
    .def_property_readonly("image_size",
        static_cast<getter_t<uint32_t>>(&Header::image_size)
    )
    .def_property_readonly("oat_checksum",
        static_cast<getter_t<uint32_t>>(&Header::oat_checksum)
    )
    .def_property_readonly("oat_file_begin",
        static_cast<getter_t<uint32_t>>(&Header::oat_file_begin)
    )
    .def_property_readonly("oat_file_end",
        static_cast<getter_t<uint32_t>>(&Header::oat_file_end)
    )
    .def_property_readonly("oat_data_end",
        static_cast<getter_t<uint32_t>>(&Header::oat_data_end)
    )
    .def_property_readonly("patch_delta",
        static_cast<getter_t<int32_t>>(&Header::patch_delta)
    )
    .def_property_readonly("image_roots",
        static_cast<getter_t<uint32_t>>(&Header::image_roots)
    )
    .def_property_readonly("pointer_size",
        static_cast<getter_t<uint32_t>>(&Header::pointer_size)
    )
    .def_property_readonly("compile_pic",
        static_cast<getter_t<bool>>(&Header::compile_pic)
    )
    .def_property_readonly("nb_sections",
        static_cast<getter_t<uint32_t>>(&Header::nb_sections)
    )
    .def_property_readonly("nb_methods",
        static_cast<getter_t<uint32_t>>(&Header::nb_methods)
    )
    .def_property_readonly("boot_image_begin",
        static_cast<getter_t<uint32_t>>(&Header::boot_image_begin)
    )
    .def_property_readonly("boot_image_size",
        static_cast<getter_t<uint32_t>>(&Header::boot_image_size)
    )
    .def_property_readonly("boot_oat_begin",
        static_cast<getter_t<uint32_t>>(&Header::boot_oat_begin)
    )
    .def_property_readonly("boot_oat_size",
        static_cast<getter_t<uint32_t>>(&Header::boot_oat_size)
    )
    .def_property_readonly("storage_mode",
        static_cast<getter_t<STORAGE_MODES>>(&Header::storage_mode)
    )
    .def_property_readonly("data_size",
        static_cast<getter_t<uint32_t>>(&Header::data_size)
    )

    .def("__eq__", &Header::operator==)
    .def("__ne__", &Header::operator!=)
    .def("__hash__",
        [] (const Header& header) {
          return Hash::hash(header);
        })

    .def("__str__",
        [] (const Header& header)
        {
          std::ostringstream stream;
          stream << header;
          std::string str =  stream.str();
          return str;
        });
}
}
}


