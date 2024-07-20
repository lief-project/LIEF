/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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

#include "LIEF/PE/signature/attributes/MsManifestBinaryID.hpp"
#include <nanobind/stl/string.h>

#include <string>
#include <sstream>

namespace LIEF::PE::py {

template<>
void create<MsManifestBinaryID>(nb::module_& m) {
  nb::class_<MsManifestBinaryID, Attribute>(m, "MsManifestBinaryID",
    R"delim(
    Interface over the structure described by the OID ``1.3.6.1.4.1.311.10.3.28`` (``szOID_PLATFORM_MANIFEST_BINARY_ID``)

    The internal structure is not documented but we can infer the following structure:

    .. code-block:: text

        szOID_PLATFORM_MANIFEST_BINARY_ID ::= SET OF BinaryID

        BinaryID ::= UTF8STRING

    )delim")

    .def_prop_rw("manifest_id",
        nb::overload_cast<>(&MsManifestBinaryID::manifest_id, nb::const_),
        nb::overload_cast<const std::string&>(&MsManifestBinaryID::manifest_id),
        "The manifest id")
    LIEF_DEFAULT_STR(MsManifestBinaryID);
}

}
