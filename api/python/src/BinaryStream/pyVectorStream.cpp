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


#include <LIEF/BinaryStream/VectorStream.hpp>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/utils.hpp>

#include "nanobind/extra/memoryview.hpp"
#include "nanobind/extra/stl/lief_result.h"
#include "typing/StrOrPath.hpp"

namespace LIEF::py {
template<>
void create<VectorStream>(nb::module_& m) {
  nb::class_<VectorStream, BinaryStream>(m, "VectorStream")
    .def_static("from_file", [] (typing::StrOrPath path) {
      return VectorStream::from_file(*path.to_string());
    }, "path"_a)

    .def_static("from_bytes", [] (nb::bytes buffer) {
      return std::make_unique<VectorStream>(nb::to_vector(buffer));
    }, "buffer"_a)

    .def_prop_ro("content", [] (VectorStream& self) {
      return nb::to_memoryview(self.content());
    })

    .def("slice", nb::overload_cast<uint32_t, size_t>(&VectorStream::slice, nb::const_),
        "offset", "size")

    .def("slice", nb::overload_cast<uint32_t>(&VectorStream::slice, nb::const_),
        "offset")
  ;
}
}
