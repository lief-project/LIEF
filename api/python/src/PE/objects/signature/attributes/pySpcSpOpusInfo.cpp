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
#include "pySafeString.hpp"

#include "LIEF/PE/signature/attributes/SpcSpOpusInfo.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<SpcSpOpusInfo>(nb::module_& m) {
  nb::class_<SpcSpOpusInfo, Attribute>(m, "SpcSpOpusInfo",
    R"delim(
    Interface over the structure described by the OID ``1.3.6.1.4.1.311.2.1.12``
    The internal structure is described in the official document: `Windows Authenticode Portable Executable Signature Format <http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx>`_

    .. code-block:: text

        SpcSpOpusInfo ::= SEQUENCE {
            programName  [0] EXPLICIT SpcString OPTIONAL,
            moreInfo     [1] EXPLICIT SpcLink OPTIONAL
        }
    )delim"_doc
  )
    .def_prop_ro("program_name",
        [] (const SpcSpOpusInfo& info) {
          return LIEF::py::safe_string(info.program_name());
        },
        "Program description provided by the publisher"_doc)

    .def_prop_ro("more_info",
        [] (const SpcSpOpusInfo& info) {
          return LIEF::py::safe_string(info.more_info());
        },
        "Other information such as an URL"_doc);
}

}
