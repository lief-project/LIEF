/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include "nanobind/extra/stl/lief_span.h"
#include "nanobind/utils.hpp"

#include "LIEF/PE/resources/ResourceIcon.hpp"
#include "pyErr.hpp"

#include <vector>
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::PE::py {

template<>
void create<ResourceIcon>(nb::module_& m) {
  nb::class_<ResourceIcon, LIEF::Object>(m, "ResourceIcon")
    .def_prop_rw("id",
        nb::overload_cast<>(&ResourceIcon::id, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceIcon::id),
        "Id associated with the icon"_doc)

    .def_prop_rw("lang",
        nb::overload_cast<>(&ResourceIcon::lang, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceIcon::lang),
        "Language associated with the icon"_doc)

    .def_prop_rw("sublang",
        nb::overload_cast<>(&ResourceIcon::sublang, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceIcon::sublang),
        "Sublanguage associated with the icon"_doc)

    .def_prop_rw("width",
        nb::overload_cast<>(&ResourceIcon::width, nb::const_),
        nb::overload_cast<uint8_t>(&ResourceIcon::width),
        "Width in pixels of the image"_doc)

    .def_prop_rw("height",
        nb::overload_cast<>(&ResourceIcon::height, nb::const_),
        nb::overload_cast<uint8_t>(&ResourceIcon::height),
        "Height in pixels of the image"_doc)

    .def_prop_rw("color_count",
        nb::overload_cast<>(&ResourceIcon::color_count, nb::const_),
        nb::overload_cast<uint8_t>(&ResourceIcon::color_count),
        "Number of colors in image (0 if >=8bpp)"_doc)

    .def_prop_rw("reserved",
        nb::overload_cast<>(&ResourceIcon::reserved, nb::const_),
        nb::overload_cast<uint8_t>(&ResourceIcon::reserved),
        "Reserved (must be 0)"_doc)

    .def_prop_rw("planes",
        nb::overload_cast<>(&ResourceIcon::planes, nb::const_),
        nb::overload_cast<uint16_t>(&ResourceIcon::planes),
        "Color Planes"_doc)

    .def_prop_rw("bit_count",
        nb::overload_cast<>(&ResourceIcon::bit_count, nb::const_),
        nb::overload_cast<uint16_t>(&ResourceIcon::bit_count),
        "Bits per pixel"_doc)

    .def_prop_rw("pixels",
        nb::overload_cast<>(&ResourceIcon::pixels, nb::const_),
        nb::overload_cast<std::vector<uint8_t>>(&ResourceIcon::pixels))

    .def("save", &ResourceIcon::save,
        "Save the icon to the given filepath"_doc,
        "filepath"_a)

    .def("serialize", [] (ResourceIcon& self) {
          return nb::to_bytes(self.serialize());
        },
        "Serialize the current icon into bytes"_doc)

    .def_static("from_serialization", [] (nb::bytes bytes) {
        return LIEF::py::error_or(
          nb::overload_cast<const uint8_t*, size_t>(&ResourceIcon::from_serialization),
          (const uint8_t*)bytes.data(), bytes.size());
      },
      "Create an icon instance from the serialized bytes"_doc)

    LIEF_DEFAULT_STR(ResourceIcon);
}

}

