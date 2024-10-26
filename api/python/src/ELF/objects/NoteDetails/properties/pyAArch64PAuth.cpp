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
#include <string>
#include <sstream>

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/NoteDetails/properties/AArch64PAuth.hpp"

namespace LIEF::ELF::py {

template<>
void create<AArch64PAuth>(nb::module_& m) {
  nb::class_<AArch64PAuth, NoteGnuProperty::Property>
    Class(m, "AArch64PAuth",
      R"doc(
      This class represents the ``GNU_PROPERTY_AARCH64_FEATURE_PAUTH`` note.

      .. note::

        If both: :attr:`.AArch64PAuth.platform` and :attr:`.AArch64PAuth.version` are set to
        0, this means that the binary is incompatible with PAuth ABI extension.
      )doc"_doc);

  Class
    .def_prop_ro("platform", &AArch64PAuth::platform,
        R"doc(
        64-bit value that specifies the platform vendor.

        A ``0`` value is associated with an *invalid* platform while the value ``1``
        is associated with a baremetal platform.
        )doc"_doc)

    .def_prop_ro("version", &AArch64PAuth::version,
        R"doc(
        64-bit value that identifies the signing schema used by the ELF file.
        )doc"_doc)
    ;

}

}
