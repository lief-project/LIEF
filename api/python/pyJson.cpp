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
#include "LIEF/config.h"
#include "LIEF/to_json.hpp"

#include "pyLIEF.hpp"

void init_json_functions(py::module& m) {

#if defined(LIEF_ELF_SUPPORT)
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::Binary,                      LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::Header,                      LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::Section,                     LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::Segment,                     LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::Note,                        LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::GnuHash,                     LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::SysvHash,                    LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::DynamicEntry,                LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::DynamicEntryArray,           LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::DynamicEntryLibrary,         LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::DynamicEntryRpath,           LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::DynamicEntryRunPath,         LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::DynamicSharedObject,         LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::DynamicEntryFlags,           LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::Symbol,                      LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::Relocation,                  LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::SymbolVersion,               LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::SymbolVersionAux,            LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::SymbolVersionAuxRequirement, LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::SymbolVersionRequirement,    LIEF::ELF::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::ELF::SymbolVersionDefinition,     LIEF::ELF::JsonVisitor>);
#endif


#if defined(LIEF_PE_SUPPORT)
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::Binary,                  LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::DosHeader,               LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::RichHeader,              LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::RichEntry,               LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::Header,                  LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::OptionalHeader,          LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::DataDirectory,           LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::Section,                 LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::Relocation,              LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::RelocationEntry,         LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::Export,                  LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ExportEntry,             LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::TLS,                     LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::Symbol,                  LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::Debug,                   LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::Import,                  LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ImportEntry,             LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ResourceNode,            LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ResourceData,            LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ResourceDirectory,       LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ResourcesManager,        LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ResourceVersion,         LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ResourceStringFileInfo,  LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ResourceFixedFileInfo,   LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ResourceVarFileInfo,     LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::LangCodeItem,            LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ResourceIcon,            LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ResourceDialog,          LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ResourceDialogItem,      LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::Signature,               LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::x509,                    LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::SignerInfo,              LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::ContentInfo,             LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::AuthenticatedAttributes, LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::AuthenticatedAttributes, LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::CodeIntegrity,           LIEF::PE::JsonVisitor>);

    m.def("to_json", &LIEF::to_json_str<LIEF::PE::LoadConfiguration,   LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::LoadConfigurationV0, LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::LoadConfigurationV1, LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::LoadConfigurationV2, LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::LoadConfigurationV3, LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::LoadConfigurationV4, LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::LoadConfigurationV5, LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::LoadConfigurationV6, LIEF::PE::JsonVisitor>);
    m.def("to_json", &LIEF::to_json_str<LIEF::PE::LoadConfigurationV7, LIEF::PE::JsonVisitor>);
#endif

    m.def("to_json",          &LIEF::to_json_str<LIEF::Binary>);
    m.def("abstract_to_json", &LIEF::to_json_str<LIEF::Binary>);
    m.def("to_json",          &LIEF::to_json_str<LIEF::Header>);
    m.def("to_json",          &LIEF::to_json_str<LIEF::Section>);
    m.def("to_json",          &LIEF::to_json_str<LIEF::Symbol>);




}
