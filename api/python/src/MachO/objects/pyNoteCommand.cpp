/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#include "nanobind/extra/stl/lief_span.h"
#include "nanobind/utils.hpp"

#include "LIEF/MachO/NoteCommand.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<NoteCommand>(nb::module_& m) {

  nb::class_<NoteCommand, LoadCommand>(m, "NoteCommand",
      R"delim(
      Class that represent the ``LC_NOTE`` command.

      This command is used to include arbitrary notes or metadata within a binary.
      )delim"_doc)

    .def_prop_rw("note_offset",
        nb::overload_cast<>(&NoteCommand::note_offset, nb::const_),
        nb::overload_cast<uint64_t>(&NoteCommand::note_offset),
        "Offset of the data associated with this note"_doc)

    .def_prop_rw("note_size",
        nb::overload_cast<>(&NoteCommand::note_size, nb::const_),
        nb::overload_cast<uint64_t>(&NoteCommand::note_size),
        "Size of the data referenced by the :attr:`~.note_offset`"_doc)

    .def_prop_ro("owner_str", &NoteCommand::owner_str,
      "Owner as a zero-terminated string"_doc)

    .def_prop_rw("owner",
        nb::overload_cast<>(&NoteCommand::owner, nb::const_),
        [] (NoteCommand& self, nb::bytes owner_bytes) {
          std::vector<uint8_t> owner = to_vector(owner_bytes);
          span<char> note_owner = self.owner();
          owner.resize(note_owner.size());
          std::copy(owner.begin(), owner.end(), note_owner.begin());
        },
        "Owner of the note (e.g. ``AIR_METALLIB``)"_doc)

    LIEF_DEFAULT_STR(NoteCommand);

}
}
