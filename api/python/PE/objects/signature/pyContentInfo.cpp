/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include <string>
#include <sstream>

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/signature/ContentInfo.hpp"

#include "pyPE.hpp"

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (ContentInfo::*)(void) const;

template<class T>
using setter_t = void (ContentInfo::*)(T);


template<>
void create<ContentInfo>(py::module& m) {

  py::class_<ContentInfo, LIEF::Object>(m, "ContentInfo")

    .def_property_readonly("content_type",
        &ContentInfo::content_type,
        "OID of the content type. This value should match ``SPC_INDIRECT_DATA_OBJID``")

     .def_property_readonly("digest_algorithm",
        &ContentInfo::digest_algorithm,
        "Algorithm (" RST_CLASS_REF(lief.PE.ALGORITHMS) ") used to hash the file. "
        "This value should match " RST_ATTR_REF_FULL(SignerInfo.digest_algorithm) " and "
        "" RST_ATTR_REF_FULL(Signature.digest_algorithm) "")

    .def_property_readonly("digest",
        [] (const ContentInfo& info) -> py::bytes {
          const std::vector<uint8_t>& dg = info.digest();
          return py::bytes(reinterpret_cast<const char*>(dg.data()), dg.size());
        },
        "The digest as ``bytes`` ")

    .def("__hash__",
        [] (const ContentInfo& info) {
          return Hash::hash(info);
        })

    .def("__str__",
        [] (const ContentInfo& content_info)
        {
          std::ostringstream stream;
          stream << content_info;
          std::string str =  stream.str();
          return str;
        });
}

}
}

