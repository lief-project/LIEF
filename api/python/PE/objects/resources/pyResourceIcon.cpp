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
#include "LIEF/PE/resources/ResourceIcon.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (ResourceIcon::*)(void) const;

template<class T>
using setter_t = void (ResourceIcon::*)(T);


template<>
void create<ResourceIcon>(py::module& m) {
  py::class_<ResourceIcon, LIEF::Object>(m, "ResourceIcon")
    .def_property("id",
        static_cast<getter_t<uint32_t>>(&ResourceIcon::id),
        static_cast<setter_t<uint32_t>>(&ResourceIcon::id),
        "Id associated with the icon")

    .def_property("lang",
        static_cast<getter_t<RESOURCE_LANGS>>(&ResourceIcon::lang),
        static_cast<setter_t<RESOURCE_LANGS>>(&ResourceIcon::lang),
        "Language (" RST_CLASS_REF(lief.PE.RESOURCE_LANGS) ") associated with the icon")

    .def_property("sublang",
        static_cast<getter_t<RESOURCE_SUBLANGS>>(&ResourceIcon::sublang),
        static_cast<setter_t<RESOURCE_SUBLANGS>>(&ResourceIcon::sublang),
        "Sub language (" RST_CLASS_REF(lief.PE.RESOURCE_SUBLANGS) ") associated with the icon")

    .def_property("width",
        static_cast<getter_t<uint8_t>>(&ResourceIcon::width),
        static_cast<setter_t<uint8_t>>(&ResourceIcon::width),
        "Width in pixels of the image")

    .def_property("height",
        static_cast<getter_t<uint8_t>>(&ResourceIcon::height),
        static_cast<setter_t<uint8_t>>(&ResourceIcon::height),
        "Height in pixels of the image")

    .def_property("color_count",
        static_cast<getter_t<uint8_t>>(&ResourceIcon::color_count),
        static_cast<setter_t<uint8_t>>(&ResourceIcon::color_count),
        "Number of colors in image (0 if >=8bpp)")

    .def_property("reserved",
        static_cast<getter_t<uint8_t>>(&ResourceIcon::reserved),
        static_cast<setter_t<uint8_t>>(&ResourceIcon::reserved),
        "Reserved (must be 0)")

    .def_property("planes",
        static_cast<getter_t<uint16_t>>(&ResourceIcon::planes),
        static_cast<setter_t<uint16_t>>(&ResourceIcon::planes),
        "Color Planes")

    .def_property("bit_count",
        static_cast<getter_t<uint16_t>>(&ResourceIcon::bit_count),
        static_cast<setter_t<uint16_t>>(&ResourceIcon::bit_count),
        "Bits per pixel")

    .def_property("pixels",
        static_cast<getter_t<const std::vector<uint8_t>&>>(&ResourceIcon::pixels),
        static_cast<setter_t<const std::vector<uint8_t>&>>(&ResourceIcon::pixels))

    .def("save",
        &ResourceIcon::save,
        "Save the icon to the given filepath",
        "filepath"_a)

    .def("__eq__", &ResourceIcon::operator==)
    .def("__ne__", &ResourceIcon::operator!=)
    .def("__hash__",
        [] (const ResourceIcon& icon) {
          return Hash::hash(icon);
        })

    .def("__str__",
        [] (const ResourceIcon& icon) {
          std::ostringstream stream;
          stream << icon;
          std::string str = stream.str();
          return str;
        });
}

}
}

