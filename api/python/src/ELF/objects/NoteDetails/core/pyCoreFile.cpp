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
#include <vector>
#include <nanobind/stl/string.h>
#include <nanobind/make_iterator.h>
#include <nanobind/stl/bind_vector.h>

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/NoteDetails/core/CoreFile.hpp"

namespace LIEF::ELF::py {

template<>
void create<CoreFile>(nb::module_& m) {
  nb::class_<CoreFile, Note> cls(m, "CoreFile");
  nb::bind_vector<CoreFile::files_t>(cls, "files_t");

  nb::class_<CoreFile::entry_t>(cls, "entry_t")
    .def_rw("start", &CoreFile::entry_t::start,
            "Start address of mapped file"_doc)

    .def_rw("end", &CoreFile::entry_t::end,
            "End address of mapped file"_doc)

    .def_rw("file_ofs", &CoreFile::entry_t::file_ofs,
             "Offset (in core) of mapped file"_doc)

    .def_rw("path", &CoreFile::entry_t::path,
            "Path of mapped file"_doc)

    LIEF_DEFAULT_STR(CoreFile::entry_t);

  cls
    .def_prop_rw("files",
        nb::overload_cast<>(&CoreFile::files, nb::const_),
        nb::overload_cast<const CoreFile::files_t&>(&CoreFile::files),
        "List of files mapped in core. (list of " RST_CLASS_REF(lief.ELF.CoreFileEntry) ")"_doc)

    .def("__len__",
        &CoreFile::count,
        "Number of files mapped in core"_doc)

    .def("__iter__",
        [&m] (const CoreFile& f) {
          return nb::make_iterator(nanobind::type<CoreFile>(), "corefile_it",
                                   std::begin(f), std::end(f));
        }, nb::keep_alive<0, 1>())

    LIEF_DEFAULT_STR(CoreFile);
}
}
