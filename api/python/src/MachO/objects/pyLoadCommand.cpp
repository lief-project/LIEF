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
#include "nanobind/extra/memoryview.hpp"
#include "nanobind/utils.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

#include "MachO/pyMachO.hpp"

#include "enums_wrapper.hpp"

namespace LIEF::MachO::py {

template<>
void create<LoadCommand>(nb::module_& m) {

  nb::class_<LoadCommand, LIEF::Object> cls(m, "LoadCommand",
      "Based class for the Mach-O load commands"_doc);
  cls
    .def(nb::init<>())

    .def_prop_rw("command",
        nb::overload_cast<>(&LoadCommand::command, nb::const_),
        nb::overload_cast<LoadCommand::TYPE>(&LoadCommand::command),
        "Command type"_doc)

    .def_prop_rw("size",
        nb::overload_cast<>(&LoadCommand::size, nb::const_),
        nb::overload_cast<uint32_t>(&LoadCommand::size),
        "Size of the command (should be greather than ``sizeof(load_command)``)"_doc)

    .def_prop_rw("data",
        [] (const LoadCommand& cmd) {
          return nb::to_memoryview(cmd.data());
        },
        nb::overload_cast<LoadCommand::raw_t>(&LoadCommand::data),
        "Command's data"_doc)

    .def_prop_rw("command_offset",
        nb::overload_cast<>(&LoadCommand::command_offset, nb::const_),
        nb::overload_cast<uint64_t>(&LoadCommand::command_offset),
        "Offset of the command within the *Load Command Table*"_doc)

    LIEF_DEFAULT_STR(LoadCommand);

  enum_<LoadCommand::TYPE>(cls, "TYPE")
  #define PY_ENUM(x) to_string(x), x
    .value(PY_ENUM(LoadCommand::TYPE::UNKNOWN))
    .value(PY_ENUM(LoadCommand::TYPE::SEGMENT))
    .value(PY_ENUM(LoadCommand::TYPE::SYMTAB))
    .value(PY_ENUM(LoadCommand::TYPE::SYMSEG))
    .value(PY_ENUM(LoadCommand::TYPE::THREAD))
    .value(PY_ENUM(LoadCommand::TYPE::UNIXTHREAD))
    .value(PY_ENUM(LoadCommand::TYPE::LOADFVMLIB))
    .value(PY_ENUM(LoadCommand::TYPE::IDFVMLIB))
    .value(PY_ENUM(LoadCommand::TYPE::IDENT))
    .value(PY_ENUM(LoadCommand::TYPE::FVMFILE))
    .value(PY_ENUM(LoadCommand::TYPE::PREPAGE))
    .value(PY_ENUM(LoadCommand::TYPE::DYSYMTAB))
    .value(PY_ENUM(LoadCommand::TYPE::LOAD_DYLIB))
    .value(PY_ENUM(LoadCommand::TYPE::ID_DYLIB))
    .value(PY_ENUM(LoadCommand::TYPE::LOAD_DYLINKER))
    .value(PY_ENUM(LoadCommand::TYPE::ID_DYLINKER))
    .value(PY_ENUM(LoadCommand::TYPE::PREBOUND_DYLIB))
    .value(PY_ENUM(LoadCommand::TYPE::ROUTINES))
    .value(PY_ENUM(LoadCommand::TYPE::SUB_FRAMEWORK))
    .value(PY_ENUM(LoadCommand::TYPE::SUB_UMBRELLA))
    .value(PY_ENUM(LoadCommand::TYPE::SUB_CLIENT))
    .value(PY_ENUM(LoadCommand::TYPE::SUB_LIBRARY))
    .value(PY_ENUM(LoadCommand::TYPE::TWOLEVEL_HINTS))
    .value(PY_ENUM(LoadCommand::TYPE::PREBIND_CKSUM))
    .value(PY_ENUM(LoadCommand::TYPE::LOAD_WEAK_DYLIB))
    .value(PY_ENUM(LoadCommand::TYPE::SEGMENT_64))
    .value(PY_ENUM(LoadCommand::TYPE::ROUTINES_64))
    .value(PY_ENUM(LoadCommand::TYPE::UUID))
    .value(PY_ENUM(LoadCommand::TYPE::RPATH))
    .value(PY_ENUM(LoadCommand::TYPE::CODE_SIGNATURE))
    .value(PY_ENUM(LoadCommand::TYPE::SEGMENT_SPLIT_INFO))
    .value(PY_ENUM(LoadCommand::TYPE::REEXPORT_DYLIB))
    .value(PY_ENUM(LoadCommand::TYPE::LAZY_LOAD_DYLIB))
    .value(PY_ENUM(LoadCommand::TYPE::ENCRYPTION_INFO))
    .value(PY_ENUM(LoadCommand::TYPE::DYLD_INFO))
    .value(PY_ENUM(LoadCommand::TYPE::DYLD_INFO_ONLY))
    .value(PY_ENUM(LoadCommand::TYPE::LOAD_UPWARD_DYLIB))
    .value(PY_ENUM(LoadCommand::TYPE::VERSION_MIN_MACOSX))
    .value(PY_ENUM(LoadCommand::TYPE::VERSION_MIN_IPHONEOS))
    .value(PY_ENUM(LoadCommand::TYPE::FUNCTION_STARTS))
    .value(PY_ENUM(LoadCommand::TYPE::DYLD_ENVIRONMENT))
    .value(PY_ENUM(LoadCommand::TYPE::MAIN))
    .value(PY_ENUM(LoadCommand::TYPE::DATA_IN_CODE))
    .value(PY_ENUM(LoadCommand::TYPE::SOURCE_VERSION))
    .value(PY_ENUM(LoadCommand::TYPE::DYLIB_CODE_SIGN_DRS))
    .value(PY_ENUM(LoadCommand::TYPE::ENCRYPTION_INFO_64))
    .value(PY_ENUM(LoadCommand::TYPE::LINKER_OPTION))
    .value(PY_ENUM(LoadCommand::TYPE::LINKER_OPTIMIZATION_HINT))
    .value(PY_ENUM(LoadCommand::TYPE::VERSION_MIN_TVOS))
    .value(PY_ENUM(LoadCommand::TYPE::VERSION_MIN_WATCHOS))
    .value(PY_ENUM(LoadCommand::TYPE::NOTE))
    .value(PY_ENUM(LoadCommand::TYPE::BUILD_VERSION))
    .value(PY_ENUM(LoadCommand::TYPE::DYLD_EXPORTS_TRIE))
    .value(PY_ENUM(LoadCommand::TYPE::DYLD_CHAINED_FIXUPS))
    .value(PY_ENUM(LoadCommand::TYPE::FILESET_ENTRY))
    .value(PY_ENUM(LoadCommand::TYPE::LIEF_UNKNOWN))
  #undef PY_ENUM
  ;


}
}
