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
#include <sstream>
#include "LIEF/MachO/Stub.hpp"

#include "nanobind/utils.hpp"
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/extra/stl/lief_span.h>

#include "MachO/pyMachO.hpp"

#include "pyLIEF.hpp"
#include "pyErr.hpp"

namespace LIEF::MachO::py {

template<>
void create<Stub>(nb::module_& m) {
  nb::class_<Stub> object(m, "Stub",
    R"doc(
    This class represents a stub entry in sections like ``__stubs,__auth_stubs``.

    It wraps assembly instructions which are used to access the *got* where the
    address of the symbol is resolved.

    Example:

    .. code-block:: text

      0000000236a3c1bc: ___memcpy_chk
        adrp            x17, #0x241513aa8
        add             x17, x17, #0x241513aa8
        ldr             x16, [x17]
        braa            x16, x17
    )doc"_doc
  );

  nb::class_<Stub::target_info_t>(object, "target_info_t")
    .def(nb::init<>())
    .def(nb::init<Header::CPU_TYPE, uint32_t>())
    .def_rw("arch", &Stub::target_info_t::arch)
    .def_rw("subtype", &Stub::target_info_t::subtype);

  object
    .def(nb::init<Stub::target_info_t, uint64_t, std::vector<uint8_t>>(),
      "target_info"_a, "address"_a, "raw_stub"_a
    )
    .def_prop_ro("address", &Stub::address,
      "The virtual address where the stub is located"_doc
    )
    .def_prop_ro("raw",
      nb::overload_cast<>(&Stub::raw, nb::const_),
      "The (raw) instructions of this entry as a memory view of bytes"_doc)

    .def_prop_ro("target",
      [] (Stub& self) {
        return LIEF::py::error_or(&Stub::target, self);
      },
      R"doc(
      The address resolved by this stub.

      For instance, given this stub:

      .. code-block::

        0x3eec: adrp    x16, #4096
        0x3ef0: ldr     x16, [x16, #24]
        0x3ef4: br      x16

      The function returns: ``0x4018``.

      .. warning::

        This function is only available with LIEF's extended version
      )doc"_doc)

  LIEF_DEFAULT_STR(Stub);
}
}
