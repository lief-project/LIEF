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
#include "LIEF/PE/signature/SignerInfo.hpp"

#include "pyPE.hpp"


template<class T>
using getter_t = T (SignerInfo::*)(void) const;

template<class T>
using setter_t = void (SignerInfo::*)(T);


void init_PE_SignerInfo_class(py::module& m) {

  py::class_<SignerInfo, LIEF::Object>(m, "SignerInfo")

    .def_property_readonly("version",
        &SignerInfo::version,
        "Should be 1")

    .def_property_readonly("issuer",
        &SignerInfo::issuer,
        "Issuer and serial number",
        py::return_value_policy::reference)

    .def_property_readonly("digest_algorithm",
        &SignerInfo::digest_algorithm,
        "Algorithm (OID) used to hash the file. This value should match ContentInfo.digest_algorithm and Signature.digest_algorithm")

    .def_property_readonly("signature_algorithm",
        &SignerInfo::signature_algorithm,
        "Return the signature algorithm (OID)")

    .def_property_readonly("encrypted_digest",
        &SignerInfo::encrypted_digest,
        "Return the signature created by the signing certificate's private key")

    .def_property_readonly("authenticated_attributes",
        &SignerInfo::authenticated_attributes,
        "Return the " RST_CLASS_REF(lief.PE.AuthenticatedAttributes) " object",
        py::return_value_policy::reference)

    .def("__str__",
        [] (const SignerInfo& signer_info)
        {
          std::ostringstream stream;
          stream << signer_info;
          std::string str =  stream.str();
          return str;
        });

}

