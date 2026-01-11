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


#include <LIEF/BinaryStream/FileStream.hpp>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/utils.hpp>

#include "typing/StrOrPath.hpp"

#include "nanobind/extra/memoryview.hpp"
#include "nanobind/extra/stl/lief_result.h"

namespace LIEF::py {
template<>
void create<FileStream>(nb::module_& m) {
  nb::class_<FileStream, BinaryStream>(m, "FileStream")
    .def_static("from_file", [] (typing::StrOrPath file) {
      return FileStream::from_file(*file.to_string());
    })
    .def_prop_ro("content", [] (FileStream& self) {
      return nb::to_bytes(self.content());
    })
  ;
}
}
