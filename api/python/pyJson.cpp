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
#include "LIEF/to_json.hpp"

#include "pyLIEF.hpp"

void init_json_functions(py::module& m) {

#if defined(LIEF_ELF_MODULE)
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::Binary,                      LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::Header,                      LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::Section,                     LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::Segment,                     LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::DynamicEntry,                LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::DynamicEntryArray,           LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::DynamicEntryLibrary,         LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::DynamicEntryRpath,           LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::DynamicEntryRunPath,         LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::DynamicSharedObject,         LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::Symbol,                      LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::Relocation,                  LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::SymbolVersion,               LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::SymbolVersionAux,            LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::SymbolVersionAuxRequirement, LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::SymbolVersionRequirement,    LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::SymbolVersionDefinition,     LIEF::ELF::JsonVisitor>);
#endif

    m.def("to_json",          &LIEF::to_json_str<LIEF::Binary>);
    m.def("abstract_to_json", &LIEF::to_json_str<LIEF::Binary>);
    m.def("to_json",          &LIEF::to_json_str<LIEF::Header>);
    m.def("to_json",          &LIEF::to_json_str<LIEF::Section>);
    m.def("to_json",          &LIEF::to_json_str<LIEF::Symbol>);




}
