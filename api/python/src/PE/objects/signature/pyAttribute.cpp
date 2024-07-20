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

#include "LIEF/PE/signature/Attribute.hpp"

#include <string>
#include <sstream>
#include "enums_wrapper.hpp"
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<Attribute>(nb::module_& m) {
  nb::class_<Attribute, Object> Class(m,
      "Attribute", "Interface over PKCS #7 attribute"_doc
  );

  #define ENTRY(X) .value(to_string(Attribute::TYPE::X), Attribute::TYPE::X)
  enum_<Attribute::TYPE>(Class, "TYPE")
    ENTRY(UNKNOWN)
    ENTRY(CONTENT_TYPE)
    ENTRY(GENERIC_TYPE)
    ENTRY(SPC_SP_OPUS_INFO)
    ENTRY(MS_COUNTER_SIGN)
    ENTRY(MS_SPC_NESTED_SIGN)
    ENTRY(MS_SPC_STATEMENT_TYPE)
    ENTRY(SPC_RELAXED_PE_MARKER_CHECK)
    ENTRY(SIGNING_CERTIFICATE_V2)
    ENTRY(MS_PLATFORM_MANIFEST_BINARY_ID)
    ENTRY(PKCS9_AT_SEQUENCE_NUMBER)
    ENTRY(PKCS9_COUNTER_SIGNATURE)
    ENTRY(PKCS9_MESSAGE_DIGEST)
    ENTRY(PKCS9_SIGNING_TIME)
  ;
  #undef ENTRY

  Class
    .def_prop_ro("type", &Attribute::type,
        "Concrete type of the attribute"_doc)

    LIEF_DEFAULT_STR(Attribute);
}
}
