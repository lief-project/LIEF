/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include <vector>

#include "pyELF.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreFile.hpp"

namespace LIEF {
namespace ELF {

template<>
void create<CoreFileEntry>(py::module& m) {

  py::class_<CoreFileEntry>(m, "CoreFileEntry")

    .def_readwrite("start", &CoreFileEntry::start,
      "Start address of mapped file")

    .def_readwrite("end", &CoreFileEntry::end,
      "End address of mapped file")

    .def_readwrite("file_ofs", &CoreFileEntry::file_ofs,
      "Offset (in core) of mapped file")

    .def_readwrite("path", &CoreFileEntry::path,
      "Path of mapped file")


    .def("__str__",
        [] (const CoreFileEntry& entry)
        {
          std::ostringstream stream;
          stream << entry;
          return stream.str();
        });

}

}
}
