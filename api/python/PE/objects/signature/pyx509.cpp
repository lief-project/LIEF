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
#include "LIEF/PE/signature/x509.hpp"

#include "pyPE.hpp"


template<class T>
using getter_t = T (x509::*)(void) const;

template<class T>
using setter_t = void (x509::*)(T);


void init_PE_x509_class(py::module& m) {

  py::class_<x509, LIEF::Object>(m, "x509")

    .def_property_readonly("version",
        &x509::version,
        "X.509 version. (1=v1, 2=v2, 3=v3)")

    .def_property_readonly("serial_number",
        &x509::serial_number,
        "Unique id for certificate issued by a specific CA.")

    .def_property_readonly("signature_algorithm",
        &x509::signature_algorithm,
        "Signature algorithm (OID)")


    .def_property_readonly("valid_from",
        &x509::valid_from,
        "Start time of certificate validity")


    .def_property_readonly("valid_to",
        &x509::valid_to,
        "End time of certificate validity")


    .def_property_readonly("issuer",
        [] (const x509& object) {
          return safe_string_converter(object.issuer());
        },
        "Issuer informations")


    .def_property_readonly("subject",
        [] (const x509& object) {
          return safe_string_converter(object.subject());
        },
        "Subject informations")


    .def("__str__",
        [] (const x509& x509_crt)
        {
          std::ostringstream stream;
          stream << x509_crt;
          std::string str =  stream.str();
          return str;
        });

}

