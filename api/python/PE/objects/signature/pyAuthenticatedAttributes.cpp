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
#include "LIEF/utils.hpp"
#include "LIEF/PE/signature/AuthenticatedAttributes.hpp"

#include "pyPE.hpp"


template<class T>
using getter_t = T (AuthenticatedAttributes::*)(void) const;

template<class T>
using setter_t = void (AuthenticatedAttributes::*)(T);


void init_PE_AuthenticatedAttributes_class(py::module& m) {

  py::class_<AuthenticatedAttributes, LIEF::Object>(m, "AuthenticatedAttributes")

    .def_property_readonly("content_type",
        &AuthenticatedAttributes::content_type,
        "Should return the ``messageDigest`` OID")

    .def_property_readonly("message_digest",
        &AuthenticatedAttributes::message_digest,
        "Return an hash of the signed attributes")

    .def_property_readonly("program_name",
        [] (const AuthenticatedAttributes& authenticated_attributes) {
          return safe_string_converter(LIEF::u16tou8(authenticated_attributes.program_name()));
        },
        "Return the program description (if any)")

    .def_property_readonly("more_info",
        [] (const AuthenticatedAttributes& obj) {
          return safe_string_converter(obj.more_info());
        },
        "Return an URL to website with more information about the signer")

    .def("__str__",
        [] (const AuthenticatedAttributes& authenticated_attributes)
        {
          std::ostringstream stream;
          stream << authenticated_attributes;
          std::string str =  stream.str();
          return str;
        });

}

