/* Copyright 2017 - 2026 R. Thomas
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
#include "pyLIEF.hpp"

#include <LIEF/BinaryStream/SpanStream.hpp>
#include <LIEF/BinaryStream/VectorStream.hpp>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/utils.hpp>

#include "nanobind/extra/memoryview.hpp"
#include "nanobind/extra/stl/lief_result.h"

namespace LIEF::py {
template<>
void create<SpanStream>(nb::module_& m) {
  nb::class_<SpanStream, BinaryStream>(m, "SpanStream")
    .def("slice", nb::overload_cast<size_t, size_t>(&SpanStream::slice, nb::const_),
      "offset"_a, "size"_a
    )

    .def("slice", nb::overload_cast<size_t>(&SpanStream::slice, nb::const_),
      "offset"_a
    )

    .def("to_vector", &SpanStream::to_vector)

    .def_prop_ro("content", [] (SpanStream& self) {
      return nb::to_bytes(self.content());
    })

    .def_prop_ro("__bytes__", [] (SpanStream& self) {
      return nb::to_bytes(self.content());
    })

  ;
}
}
