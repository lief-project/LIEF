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

#include "LIEF/PE/signature/ContentInfo.hpp"
#include "LIEF/PE/signature/SpcIndirectData.hpp"
#include "LIEF/PE/signature/GenericContent.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

#include "nanobind/utils.hpp"

namespace LIEF::PE::py {

template<>
void create<ContentInfo>(nb::module_& m) {

  nb::class_<ContentInfo, Object> info(m, "ContentInfo",
      R"delim(
      ContentInfo as described in the `RFC 2315 <https://tools.ietf.org/html/rfc2315#section-7>`_

      .. code-block:: text

        ContentInfo ::= SEQUENCE {
          contentType ContentType,
          content     [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
        }

        ContentType ::= OBJECT IDENTIFIER

      In the case of PE signature, ContentType **must** be set to SPC_INDIRECT_DATA_OBJID
      OID: ``1.3.6.1.4.1.311.2.1.4`` and content is defined by the structure: ``SpcIndirectDataContent``

      .. code-block:: text

        SpcIndirectDataContent ::= SEQUENCE {
         data          SpcAttributeTypeAndOptionalValue,
         messageDigest DigestInfo
        }

        SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
         type  ObjectID,
         value [0] EXPLICIT ANY OPTIONAL
        }

      For PE signature, ``SpcAttributeTypeAndOptionalValue.type``
      is set to ``SPC_PE_IMAGE_DATAOBJ`` (OID: ``1.3.6.1.4.1.311.2.1.15``) and the value is defined by
      ``SpcPeImageData``

      .. code-block:: text

        DigestInfo ::= SEQUENCE {
         digestAlgorithm  AlgorithmIdentifier,
         digest           OCTETSTRING
        }

        AlgorithmIdentifier ::= SEQUENCE {
         algorithm  ObjectID,
         parameters [0] EXPLICIT ANY OPTIONAL
        }
      )delim"_doc);

  nb::class_<ContentInfo::Content, Object> content(info, "Content");
  content
    .def_prop_ro("content_type",
        &ContentInfo::Content::content_type,
        "OID of the content type. This value should match ``SPC_INDIRECT_DATA_OBJID``"_doc)
    LIEF_CLONABLE(ContentInfo::Content);

  info
    .def_prop_ro("content_type",
        &ContentInfo::content_type,
        "An alias for :attr:`~.ContentInfo.content_type`"_doc)

    .def_prop_ro("digest",
        [] (const ContentInfo& self) -> nb::bytes {
          return nb::to_bytes(self.digest());
        },
        R"delim(
        Return the digest (authentihash) if the underlying content type is
        ``SPC_INDIRECT_DATA_OBJID``. Return empty bytes otherwise.
        )delim"_doc
    )
    .def_prop_ro("digest_algorithm", &ContentInfo::digest_algorithm,
                 "Return the hash algorithm used to generate the :attr:`.digest`"_doc)

    .def_prop_ro("value", nb::overload_cast<>(&ContentInfo::value),
                 nb::rv_policy::reference_internal)

    LIEF_COPYABLE(ContentInfo)
    LIEF_DEFAULT_STR(ContentInfo);
}

}

