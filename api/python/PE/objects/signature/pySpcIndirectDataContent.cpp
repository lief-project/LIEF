/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 * Copyright 2020 K. Nakagawa
 *
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

#include "LIEF/PE/hash.hpp"
#include "LIEF/utils.hpp"
#include "LIEF/PE/signature/SpcIndirectDataContent.hpp"

#include "pyPE.hpp"

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (SpcIndirectDataContent::*)(void) const;

template<class T>
using setter_t = void (SpcIndirectDataContent::*)(T);


template<>
void create<SpcIndirectDataContent>(py::module& m) {

  py::class_<SpcIndirectDataContent, LIEF::Object>(m, "SpcIndirectDataContent")

    .def_property_readonly("digest_algorithm",
        &SpcIndirectDataContent::digest_algorithm,
        "Return the ``digestAlgorithm`` OID")
    .def_property_readonly("flags",
        &SpcIndirectDataContent::flags,
        "Return the flags field of SpcPeImageData")
    .def_property_readonly("file",
        &SpcIndirectDataContent::file,
        "Return the file field of SpcPeImageData")
    .def_property_readonly("type",
        &SpcIndirectDataContent::type,
        "Return the SPC_PE_IMAGE_DATAOBJ OID")
    .def_property_readonly("digest",
        &SpcIndirectDataContent::digest,
        "Return the message digest value of the file",
        py::return_value_policy::reference_internal)
    .def("__str__",
        [] (const SpcIndirectDataContent& spc_indirect_data_content)
        {
          std::stringstream ss;
          ss << spc_indirect_data_content;
          return ss.str();
        });

}

}
}
