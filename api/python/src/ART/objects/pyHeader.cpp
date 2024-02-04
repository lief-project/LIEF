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
#include "LIEF/ART/Header.hpp"

#include "ART/pyART.hpp"

#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/array.h>

namespace LIEF::ART::py {

template<>
void create<Header>(nb::module_& m) {

  nb::class_<Header, Object>(m, "Header", "ART Header representation"_doc)
    .def_prop_ro("magic",
        nb::overload_cast<>(&Header::magic, nb::const_)
    )
    .def_prop_ro("version",
        nb::overload_cast<>(&Header::version, nb::const_)
    )
    .def_prop_ro("image_begin",
        nb::overload_cast<>(&Header::image_begin, nb::const_)
    )
    .def_prop_ro("image_size",
        nb::overload_cast<>(&Header::image_size, nb::const_)
    )
    .def_prop_ro("oat_checksum",
        nb::overload_cast<>(&Header::oat_checksum, nb::const_)
    )
    .def_prop_ro("oat_file_begin",
        nb::overload_cast<>(&Header::oat_file_begin, nb::const_)
    )
    .def_prop_ro("oat_file_end",
        nb::overload_cast<>(&Header::oat_file_end, nb::const_)
    )
    .def_prop_ro("oat_data_end",
        nb::overload_cast<>(&Header::oat_data_end, nb::const_)
    )
    .def_prop_ro("patch_delta",
        nb::overload_cast<>(&Header::patch_delta, nb::const_)
    )
    .def_prop_ro("image_roots",
        nb::overload_cast<>(&Header::image_roots, nb::const_)
    )
    .def_prop_ro("pointer_size",
        nb::overload_cast<>(&Header::pointer_size, nb::const_)
    )
    .def_prop_ro("compile_pic",
        nb::overload_cast<>(&Header::compile_pic, nb::const_)
    )
    .def_prop_ro("nb_sections",
        nb::overload_cast<>(&Header::nb_sections, nb::const_)
    )
    .def_prop_ro("nb_methods",
        nb::overload_cast<>(&Header::nb_methods, nb::const_)
    )
    .def_prop_ro("boot_image_begin",
        nb::overload_cast<>(&Header::boot_image_begin, nb::const_)
    )
    .def_prop_ro("boot_image_size",
        nb::overload_cast<>(&Header::boot_image_size, nb::const_)
    )
    .def_prop_ro("boot_oat_begin",
        nb::overload_cast<>(&Header::boot_oat_begin, nb::const_)
    )
    .def_prop_ro("boot_oat_size",
        nb::overload_cast<>(&Header::boot_oat_size, nb::const_)
    )
    .def_prop_ro("storage_mode",
        nb::overload_cast<>(&Header::storage_mode, nb::const_)
    )
    .def_prop_ro("data_size",
        nb::overload_cast<>(&Header::data_size, nb::const_)
    )

    LIEF_DEFAULT_STR(Header);
}
}


