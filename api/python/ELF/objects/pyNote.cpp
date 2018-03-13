/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/Note.hpp"

template<class T>
using getter_t = T (Note::*)(void) const;

template<class T>
using setter_t = void (Note::*)(T);

void init_ELF_Note_class(py::module& m) {

  py::class_<Note, LIEF::Object>(m, "Note")
    .def(py::init<>(),
        "Default ctor")

    .def(py::init<const std::string&, NOTE_TYPES, const std::vector<uint8_t>&>(),
        "Ctor from ``name``, ``type`` and ``description``",
        "name"_a, "type"_a, "description"_a)

    .def_property("name",
        static_cast<getter_t<const std::string&>>(&Note::name),
        static_cast<setter_t<const std::string&>>(&Note::name),
        "Return the *name* of the note (Usually the owner)."
        )

    .def_property("type",
        static_cast<getter_t<NOTE_TYPES>>(&Note::type),
        static_cast<setter_t<NOTE_TYPES>>(&Note::type),
        "Return the type of the note. Can be one of the " RST_CLASS_REF(lief.ELF.NOTE_TYPES) " values"
        )

    .def_property("description",
        static_cast<getter_t<const Note::description_t&>>(&Note::description),
        static_cast<setter_t<const Note::description_t&>>(&Note::description),
        "Return the description associated with the note"
        )

    .def_property_readonly("abi",
        static_cast<getter_t<NOTE_ABIS>>(&Note::abi),
        "Return the target " RST_CLASS_REF(lief.ELF.NOTE_TYPES) ". Require a :attr:`~lief.ELF.NOTE_TYPES.ABI_TAG` :attr:`~lief.ELF.Note.type`"
        )

    .def_property_readonly("version",
        static_cast<getter_t<Note::version_t>>(&Note::version),
        "Return the target version as ``(Major, Minor, Patch)``. Require a :attr:`~lief.ELF.NOTE_TYPES.ABI_TAG` :attr:`~lief.ELF.Note.type`"
        )

    .def("__eq__", &Note::operator==)
    .def("__ne__", &Note::operator!=)
    .def("__hash__",
        [] (const Note& note) {
          return Hash::hash(note);
        })

    .def("__str__",
        [] (const Note& note)
        {
          std::ostringstream stream;
          stream << note;
          std::string str = stream.str();
          return str;
        });
}
