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


template<class T>
using getter_t = T (ContentInfo::*)(void) const;

template<class T>
using setter_t = void (ContentInfo::*)(T);


void init_PE_ContentInfo_class(py::module& m) {

  py::class_<ContentInfo, LIEF::Object>(m, "ContentInfo")

    .def_property_readonly("content_type",
        &ContentInfo::content_type,
        "OID of the content type. This value should match ``SPC_INDIRECT_DATA_OBJID``")

    .def_property_readonly("type",
        &ContentInfo::type)

    .def_property_readonly("digest_algorithm",
        &ContentInfo::digest_algorithm,
        "Algorithm (OID) used to hash the file. This value should match SignerInfo.digest_algorithm and Signature.digest_algorithm")


    .def_property_readonly("digest",
        &ContentInfo::digest,
        "The digest")


    .def("__str__",
        [] (const ContentInfo& content_info)
        {
          std::ostringstream stream;
          stream << content_info;
          std::string str =  stream.str();
          return str;
        });

}

