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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/signature/Attribute.hpp"
#include "LIEF/PE/signature/attributes/MsSpcStatementType.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (MsSpcStatementType::*)(void) const;

template<class T>
using setter_t = void (MsSpcStatementType::*)(T);


template<>
void create<MsSpcStatementType>(py::module& m) {
  py::class_<MsSpcStatementType, Attribute>(m, "MsSpcStatementType",
    R"delim(
    Interface over the structure described by the OID ``1.3.6.1.4.1.311.2.1.11``

    The internal structure is described in the official document:
    `Windows Authenticode Portable Executable Signature Format <http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx>`_

    .. code-block:: text

        SpcStatementType ::= SEQUENCE of OBJECT IDENTIFIER

    )delim")

    .def_property_readonly("oid",
        &MsSpcStatementType::oid,
        R"delim(
        According to the documentation:

        ::

          The SpcStatementType MUST contain one Object Identifier with either
          the value ``1.3.6.1.4.1.311.2.1.21 (SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID)`` or
          ``1.3.6.1.4.1.311.2.1.22 (SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID)``.
        )delim")

    .def("__hash__",
        [] (const MsSpcStatementType& obj) {
          return Hash::hash(obj);
        })

    .def("__str__", &MsSpcStatementType::print);
}

}
}
