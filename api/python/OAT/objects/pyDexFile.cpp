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
#include "LIEF/OAT/DexFile.hpp"
#include "LIEF/OAT/hash.hpp"

#include "pyOAT.hpp"

namespace LIEF {
namespace OAT {

template<class T>
using getter_t = T (DexFile::*)(void) const;

template<class T>
using setter_t = void (DexFile::*)(T);

template<class T>
using no_const_getter = T (DexFile::*)(void);

template<>
void create<DexFile>(py::module& m) {

  py::class_<DexFile, LIEF::Object>(m, "DexFile", "OAT DexFile representation")
    .def(py::init<>())

    .def_property("location",
        static_cast<getter_t<const std::string&>>(&DexFile::location),
        static_cast<setter_t<const std::string&>>(&DexFile::location),
        "Original location of the DEX file")

    .def_property("checksum",
        static_cast<getter_t<uint32_t>>(&DexFile::checksum),
        static_cast<setter_t<uint32_t>>(&DexFile::checksum),
        "Checksum of the underlying DEX file")

    .def_property("dex_offset",
        static_cast<getter_t<uint32_t>>(&DexFile::dex_offset),
        static_cast<setter_t<uint32_t>>(&DexFile::dex_offset),
        "Offset to the raw " RST_CLASS_REF_FULL(lief.DEX.File) "")

    .def_property_readonly("has_dex_file",
        &DexFile::has_dex_file,
        "Check if the " RST_CLASS_REF_FULL(lief.DEX.File) " is present")

    .def_property_readonly("dex_file",
        static_cast<no_const_getter<LIEF::DEX::File*>>(&DexFile::dex_file),
        "Associated " RST_CLASS_REF_FULL(lief.DEX.File) "")

    .def("__eq__", &DexFile::operator==)
    .def("__ne__", &DexFile::operator!=)
    .def("__hash__",
        [] (const DexFile& dex_file) {
          return Hash::hash(dex_file);
        })

    .def("__str__",
        [] (const DexFile& dexfile) {
          std::ostringstream stream;
          stream << dexfile;
          return stream.str();
        });
}

}
}

