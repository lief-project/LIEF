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
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>
#include "nanobind/extra/memoryview.hpp"
#include "nanobind/utils.hpp"

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails.hpp"

#include "enums_wrapper.hpp"

namespace LIEF::ELF::py {

template<>
void create<Note>(nb::module_& m) {
  nb::class_<Note, Object> note(m, "Note",
      R"delim(
      Class which represents an ELF note.
      )delim"_doc);

  #define ENTRY(X) .value(to_string(Note::TYPE::X), Note::TYPE::X)
  enum_<Note::TYPE>(note, "TYPE", "LIEF representation of the ELF `NT_` values.")
    ENTRY(UNKNOWN)
    ENTRY(GNU_ABI_TAG)
    ENTRY(GNU_HWCAP)
    ENTRY(GNU_ABI_TAG)
    ENTRY(GNU_HWCAP)
    ENTRY(GNU_BUILD_ID)
    ENTRY(GNU_GOLD_VERSION)
    ENTRY(GNU_PROPERTY_TYPE_0)
    ENTRY(GNU_BUILD_ATTRIBUTE_OPEN)
    ENTRY(GNU_BUILD_ATTRIBUTE_FUNC)
    ENTRY(CRASHPAD)
    ENTRY(CORE_PRSTATUS)
    ENTRY(CORE_FPREGSET)
    ENTRY(CORE_PRPSINFO)
    ENTRY(CORE_TASKSTRUCT)
    ENTRY(CORE_AUXV)
    ENTRY(CORE_PSTATUS)
    ENTRY(CORE_FPREGS)
    ENTRY(CORE_PSINFO)
    ENTRY(CORE_LWPSTATUS)
    ENTRY(CORE_LWPSINFO)
    ENTRY(CORE_WIN32PSTATUS)
    ENTRY(CORE_FILE)
    ENTRY(CORE_PRXFPREG)
    ENTRY(CORE_SIGINFO)
    ENTRY(CORE_ARM_VFP)
    ENTRY(CORE_ARM_TLS)
    ENTRY(CORE_ARM_HW_BREAK)
    ENTRY(CORE_ARM_HW_WATCH)
    ENTRY(CORE_ARM_SYSTEM_CALL)
    ENTRY(CORE_ARM_SVE)
    ENTRY(CORE_ARM_PAC_MASK)
    ENTRY(CORE_ARM_PACA_KEYS)
    ENTRY(CORE_ARM_PACG_KEYS)
    ENTRY(CORE_TAGGED_ADDR_CTRL)
    ENTRY(CORE_PAC_ENABLED_KEYS)
    ENTRY(CORE_X86_TLS)
    ENTRY(CORE_X86_IOPERM)
    ENTRY(CORE_X86_XSTATE)
    ENTRY(CORE_X86_CET)
    ENTRY(ANDROID_MEMTAG)
    ENTRY(ANDROID_KUSER)
    ENTRY(ANDROID_IDENT)
    ENTRY(GO_BUILDID)
    ENTRY(STAPSDT)
    ENTRY(QNX_STACK)
  ;
  #undef ENTRY

  const auto create_overload_0 = nb::overload_cast<const std::string&, uint32_t, Note::description_t, std::string, Header::FILE_TYPE, ARCH, Header::CLASS>(&Note::create);
  const auto create_overload_1 = nb::overload_cast<const std::string&, Note::TYPE, Note::description_t, std::string, ARCH, Header::CLASS>(&Note::create);
  note
    .def_static("create", create_overload_0,
      R"doc(
      Create a note from the owner name, the original type (`NT_xxx` value)
      and the description.

      Depending on the note, the filetype, the architecture and the ELF class might be needed.
      )doc"_doc,
      "name"_a, "original_type"_a, "description"_a, "section_name"_a,
      "file_type"_a = Header::FILE_TYPE::NONE, "arch"_a = ARCH::NONE, "cls"_a = Header::CLASS::NONE)

    .def_static("create",
      [] (nb::bytes bytes, std::string section, Header::FILE_TYPE ftype, ARCH arch, Header::CLASS cls) -> std::unique_ptr<Note> {
        std::unique_ptr<LIEF::SpanStream> stream = to_stream(bytes);
        if (!stream) {
          return nullptr;
        }
        return Note::create(*stream, std::move(section), ftype, arch, cls);
      },
      R"doc(
      Create a note from the given `bytes` buffer.

      Depending on the note, the filetype, the architecture and the ELF class might
      be needed.
      )doc"_doc,
      "raw"_a, "section_name"_a = "",
      "file_type"_a = Header::FILE_TYPE::NONE, "arch"_a = ARCH::NONE,
      "cls"_a = Header::CLASS::NONE)

    .def_static("create", create_overload_1,
      R"doc(
      Create the owner name, the type and the description

      Depending on the note, the filetype, the architecture and the ELF class might
      be needed.
      )doc"_doc,
      "name"_a, "type"_a, "description"_a, "section_name"_a,
      "arch"_a = ARCH::NONE, "cls"_a = Header::CLASS::NONE)

    .def_prop_rw("name",
        nb::overload_cast<>(&Note::name, nb::const_),
        nb::overload_cast<std::string>(&Note::name),
        "Return the *name* of the note also known as the owner."_doc)

    .def_prop_ro("original_type",
        nb::overload_cast<>(&Note::original_type, nb::const_),
        R"doc(
        Return the original `NT_` value of the note.

        This value should be interpreted according the the :attr:`~.name` of the
        note.
        )doc"_doc)

    .def_prop_ro("type",
        nb::overload_cast<>(&Note::type, nb::const_),
        R"doc(
        Return the LIEF type representation of the note.
        )doc"_doc)

    .def_prop_rw("description",
        [] (const Note& self) {
          return nb::to_memoryview(self.description());
        },
        nb::overload_cast<Note::description_t>(&Note::description),
        "Return the description associated with the note"_doc)

    .def_prop_ro("size", &Note::size, "Size of the **raw** note"_doc)

    LIEF_CLONABLE(Note)
    LIEF_DEFAULT_STR(Note);
}

}

