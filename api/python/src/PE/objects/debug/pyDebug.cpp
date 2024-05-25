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

#include "LIEF/PE/Debug.hpp"

#include "enums_wrapper.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

#define PY_ENUM(x) to_string(x), x

namespace LIEF::PE::py {

template<>
void create<Debug>(nb::module_& m) {
  nb::class_<Debug, LIEF::Object> debug(m, "Debug",
    R"delim(
    This class represents a generic entry in the debug data directory.
    For known types, this class is extended to provide a dedicated API
    (see: ! CodeCodeView)
    )delim"_doc);

  enum_<Debug::TYPES>(debug, "TYPES", "The entry types")
    .value(PY_ENUM(Debug::TYPES::UNKNOWN))
    .value(PY_ENUM(Debug::TYPES::COFF), "COFF debug information"_doc)
    .value(PY_ENUM(Debug::TYPES::CODEVIEW), "CodeView debug information (pdb & cie)"_doc)
    .value(PY_ENUM(Debug::TYPES::FPO), "Frame pointer omission information"_doc)
    .value(PY_ENUM(Debug::TYPES::MISC), "CodeView Debug Information"_doc)
    .value(PY_ENUM(Debug::TYPES::EXCEPTION), "A copy of .pdata section."_doc)
    .value(PY_ENUM(Debug::TYPES::FIXUP), "Reserved"_doc)
    .value(PY_ENUM(Debug::TYPES::OMAP_TO_SRC), "The mapping from an RVA in image to an RVA in source image."_doc)
    .value(PY_ENUM(Debug::TYPES::OMAP_FROM_SRC), "The mapping from an RVA in source image to an RVA in image."_doc)
    .value(PY_ENUM(Debug::TYPES::BORLAND), "Reserved for Borland."_doc)
    .value(PY_ENUM(Debug::TYPES::RESERVED10), "Reserved"_doc)
    .value(PY_ENUM(Debug::TYPES::CLSID), "Reserved"_doc)
    .value(PY_ENUM(Debug::TYPES::VC_FEATURE))
    .value(PY_ENUM(Debug::TYPES::POGO), "Profile Guided Optimization metadata"_doc)
    .value(PY_ENUM(Debug::TYPES::ILTCG))
    .value(PY_ENUM(Debug::TYPES::MPX))
    .value(PY_ENUM(Debug::TYPES::REPRO), "PE determinism or reproducibility"_doc)
    .value(PY_ENUM(Debug::TYPES::EX_DLLCHARACTERISTICS));

  debug
    .def(nb::init<>())

    .def_prop_rw("characteristics",
        nb::overload_cast<>(&Debug::characteristics, nb::const_),
        nb::overload_cast<uint32_t>(&Debug::characteristics),
        "Reserved should be 0"_doc)

    .def_prop_rw("timestamp",
        nb::overload_cast<>(&Debug::timestamp, nb::const_),
        nb::overload_cast<uint32_t>(&Debug::timestamp),
        "The time and date when the debug data was created."_doc)

    .def_prop_rw("major_version",
        nb::overload_cast<>(&Debug::major_version, nb::const_),
        nb::overload_cast<uint16_t>(&Debug::major_version),
        "The major version number of the debug data format."_doc)

    .def_prop_rw("minor_version",
        nb::overload_cast<>(&Debug::minor_version, nb::const_),
        nb::overload_cast<uint16_t>(&Debug::minor_version),
        "The minor version number of the debug data format."_doc)

    .def_prop_ro("type",
        nb::overload_cast<>(&Debug::type, nb::const_),
        "The format (" RST_CLASS_REF(lief.PE.Debug.TYPES) ") of the debugging information"_doc)

    .def_prop_rw("sizeof_data",
        nb::overload_cast<>(&Debug::sizeof_data, nb::const_),
        nb::overload_cast<uint32_t>(&Debug::sizeof_data),
        "Size of the debug data"_doc)

    .def_prop_rw("addressof_rawdata",
        nb::overload_cast<>(&Debug::addressof_rawdata, nb::const_),
        nb::overload_cast<uint32_t>(&Debug::addressof_rawdata),
        "Address of the debug data relative to the image base"_doc)

    .def_prop_rw("pointerto_rawdata",
        nb::overload_cast<>(&Debug::pointerto_rawdata, nb::const_),
        nb::overload_cast<uint32_t>(&Debug::pointerto_rawdata),
        "File offset of the debug data"_doc)

    LIEF_CLONABLE(Debug)
    LIEF_DEFAULT_STR(Debug);
}

}

