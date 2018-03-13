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
#include "LIEF/PE/signature/Signature.hpp"

#include "pyPE.hpp"


template<class T>
using getter_t = T (Signature::*)(void) const;

template<class T>
using setter_t = void (Signature::*)(T);


void init_PE_Signature_class(py::module& m) {

  py::class_<Signature, LIEF::Object>(m, "Signature")

    .def_property_readonly("version",
        &Signature::version,
        "Should be 1")

    .def_property_readonly("digest_algorithm",
        &Signature::digest_algorithm,
        "Return the algorithm (OID) used to sign the content of " RST_CLASS_REF(lief.PE.ContentInfo) "")


    .def_property_readonly("content_info",
        &Signature::content_info,
        "Return the " RST_CLASS_REF(lief.PE.ContentInfo) "",
        py::return_value_policy::reference)


    .def_property_readonly("certificates",
        &Signature::certificates,
        "Return an iterator over " RST_CLASS_REF(lief.PE.x509) " certificates",
        py::return_value_policy::reference)


    .def_property_readonly("signer_info",
        &Signature::signer_info,
        "Return the " RST_CLASS_REF(lief.PE.SignerInfo) "",
        py::return_value_policy::reference)


    .def_property_readonly("original_signature",
        &Signature::original_signature,
        "Return the raw original signature")


    .def("__str__",
        [] (const Signature& signature)
        {
          std::ostringstream stream;
          stream << signature;
          std::string str =  stream.str();
          return str;
        });

}

