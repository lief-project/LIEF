/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include "LIEF/PE/exceptions_info/AArch64/UnpackedFunction.hpp"
#include "pyIterator.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "nanobind/extra/stl/lief_span.h"

namespace LIEF::PE::py {

using namespace unwind_aarch64;

template<>
void create<UnpackedFunction>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<UnpackedFunction, RuntimeFunctionAArch64> unpacked(m, "UnpackedFunction",
    R"doc(
    This class represents an unpacked AArch64 exception entry

    Reference: https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170#xdata-records
    )doc"_doc);

  using epilog_scope_t = UnpackedFunction::epilog_scope_t;

  nb::class_<epilog_scope_t>(unpacked, "epilog_scope_t",
    R"doc(
    This strucure describes an epilog scope.
    )doc"_doc
  )
    .def_rw("start_offset", &epilog_scope_t::start_offset,
      R"doc(
      Offset of the epilog relatives to the start of the function
      )doc"_doc
    )
    .def_rw("start_index", &epilog_scope_t::start_index,
      R"doc(
      Byte index of the first unwind code that describes this epilog
      )doc"_doc
    )
    .def_rw("reserved", &epilog_scope_t::reserved,
      R"doc(
      Reserved for future expansion. Should be 0.
      )doc"_doc
    )
  ;

  init_ref_iterator<UnpackedFunction::it_epilog_scopes>(unpacked, "it_epilog_scopes");

  unpacked
    .def_prop_rw("xdata_rva",
      nb::overload_cast<>(&UnpackedFunction::xdata_rva, nb::const_),
      nb::overload_cast<uint32_t>(&UnpackedFunction::xdata_rva),
      "RVA where this unpacked data is located (usually pointing in ``.xdata``)"_doc
    )

    .def_prop_rw("version",
      nb::overload_cast<>(&UnpackedFunction::version, nb::const_),
      nb::overload_cast<uint32_t>(&UnpackedFunction::version),
      R"doc(
      Describes the version of the remaining ``.xdata``.

      Currently (2025-01-04), only version 0 is defined, so values of 1-3 aren't
      permitted.
      )doc"_doc
    )

    .def_prop_rw("X",
      nb::overload_cast<>(&UnpackedFunction::X, nb::const_),
      nb::overload_cast<uint8_t>(&UnpackedFunction::X),
      R"doc(
      1-bit field that indicates the presence (1) or absence (0) of exception
      data.
      )doc"_doc
    )

    .def_prop_rw("E",
      nb::overload_cast<>(&UnpackedFunction::E, nb::const_),
      nb::overload_cast<uint8_t>(&UnpackedFunction::E),
      R"doc(
      1-bit field that indicates that information describing a single epilog is
      packed into the header (1) rather than requiring more scope words later (0).
      )doc"_doc
    )

    .def_prop_ro("epilog_count", &UnpackedFunction::epilog_count,
      R"doc(
      **If E == 0**, specifies the count of the total number of epilog scopes.
      Otherwise, return 0.
      )doc"_doc
    )
    .def_prop_ro("epilog_offset", &UnpackedFunction::epilog_offset,
      R"doc(
      **If E() == 1**, index of the first unwind code that describes the one and
      only epilog.
      )doc"_doc
    )
    .def_prop_rw("code_words",
      nb::overload_cast<>(&UnpackedFunction::code_words, nb::const_),
      nb::overload_cast<uint32_t>(&UnpackedFunction::code_words),
      R"doc(
      Number of 32-bit words needed to contain all of the unwind codes
      )doc"_doc)

    .def_prop_rw("exception_handler",
      nb::overload_cast<>(&UnpackedFunction::exception_handler, nb::const_),
      nb::overload_cast<uint32_t>(&UnpackedFunction::exception_handler),
      "Exception handler RVA (if any)"_doc)

    .def_prop_rw("unwind_code",
      nb::overload_cast<>(&UnpackedFunction::unwind_code),
      nb::overload_cast<std::vector<uint8_t>>(&UnpackedFunction::unwind_code),
      "Bytes that contain unwind codes"_doc
    )

    .def_prop_ro("epilog_scopes",
      nb::overload_cast<>(&UnpackedFunction::epilog_scopes),
      nb::rv_policy::reference_internal, nb::keep_alive<0, 1>(),
      "Iterator over the epilog scopes"_doc
    )
  ;
}

}
