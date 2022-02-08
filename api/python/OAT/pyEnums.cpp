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
#include "pyOAT.hpp"
#include "LIEF/OAT/enums.hpp"
#include "LIEF/OAT/EnumToString.hpp"

#define PY_ENUM(x) to_string(x), x

namespace LIEF {
namespace OAT {

void init_enums(py::module& m) {

  py::enum_<OAT_CLASS_TYPES>(m, "OAT_CLASS_TYPES")
    .value(PY_ENUM(OAT_CLASS_TYPES::OAT_CLASS_ALL_COMPILED))
    .value(PY_ENUM(OAT_CLASS_TYPES::OAT_CLASS_SOME_COMPILED))
    .value(PY_ENUM(OAT_CLASS_TYPES::OAT_CLASS_NONE_COMPILED));

  py::enum_<OAT_CLASS_STATUS>(m, "OAT_CLASS_STATUS")
    .value(PY_ENUM(OAT_CLASS_STATUS::STATUS_RETIRED))
    .value(PY_ENUM(OAT_CLASS_STATUS::STATUS_ERROR))
    .value(PY_ENUM(OAT_CLASS_STATUS::STATUS_NOTREADY))
    .value(PY_ENUM(OAT_CLASS_STATUS::STATUS_IDX))
    .value(PY_ENUM(OAT_CLASS_STATUS::STATUS_LOADED))
    .value(PY_ENUM(OAT_CLASS_STATUS::STATUS_RESOLVING))
    .value(PY_ENUM(OAT_CLASS_STATUS::STATUS_RESOLVED))
    .value(PY_ENUM(OAT_CLASS_STATUS::STATUS_VERIFYING))
    .value(PY_ENUM(OAT_CLASS_STATUS::STATUS_RETRY_VERIFICATION_AT_RUNTIME))
    .value(PY_ENUM(OAT_CLASS_STATUS::STATUS_VERIFYING_AT_RUNTIME))
    .value(PY_ENUM(OAT_CLASS_STATUS::STATUS_VERIFIED))
    .value(PY_ENUM(OAT_CLASS_STATUS::STATUS_INITIALIZING))
    .value(PY_ENUM(OAT_CLASS_STATUS::STATUS_INITIALIZED));

  py::enum_<HEADER_KEYS>(m, "HEADER_KEYS")
    .value(PY_ENUM(HEADER_KEYS::KEY_IMAGE_LOCATION))
    .value(PY_ENUM(HEADER_KEYS::KEY_DEX2OAT_CMD_LINE))
    .value(PY_ENUM(HEADER_KEYS::KEY_DEX2OAT_HOST))
    .value(PY_ENUM(HEADER_KEYS::KEY_PIC))
    .value(PY_ENUM(HEADER_KEYS::KEY_HAS_PATCH_INFO))
    .value(PY_ENUM(HEADER_KEYS::KEY_DEBUGGABLE))
    .value(PY_ENUM(HEADER_KEYS::KEY_NATIVE_DEBUGGABLE))
    .value(PY_ENUM(HEADER_KEYS::KEY_COMPILER_FILTER))
    .value(PY_ENUM(HEADER_KEYS::KEY_CLASS_PATH))
    .value(PY_ENUM(HEADER_KEYS::KEY_BOOT_CLASS_PATH))
    .value(PY_ENUM(HEADER_KEYS::KEY_CONCURRENT_COPYING));


  py::enum_<INSTRUCTION_SETS>(m, "INSTRUCTION_SETS")
    .value(PY_ENUM(INSTRUCTION_SETS::INST_SET_NONE))
    .value(PY_ENUM(INSTRUCTION_SETS::INST_SET_ARM))
    .value(PY_ENUM(INSTRUCTION_SETS::INST_SET_ARM_64))
    .value(PY_ENUM(INSTRUCTION_SETS::INST_SET_THUMB2))
    .value(PY_ENUM(INSTRUCTION_SETS::INST_SET_X86))
    .value(PY_ENUM(INSTRUCTION_SETS::INST_SET_X86_64))
    .value(PY_ENUM(INSTRUCTION_SETS::INST_SET_MIPS))
    .value(PY_ENUM(INSTRUCTION_SETS::INST_SET_MIPS_64));

}

}
}
