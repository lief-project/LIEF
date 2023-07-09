/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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
#include <nanobind/stl/string.h>

#include "ELF/pyELF.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreFile.hpp"

namespace LIEF::ELF::py {

template<>
void create<CoreFileEntry>(nb::module_& m) {

  nb::class_<CoreFileEntry>(m, "CoreFileEntry")

    .def_rw("start", &CoreFileEntry::start,
      "Start address of mapped file"_doc)

    .def_rw("end", &CoreFileEntry::end,
      "End address of mapped file"_doc)

    .def_rw("file_ofs", &CoreFileEntry::file_ofs,
      "Offset (in core) of mapped file"_doc)

    .def_rw("path", &CoreFileEntry::path,
      "Path of mapped file"_doc)

    LIEF_DEFAULT_STR(LIEF::ELF::CoreFileEntry);
}

}
