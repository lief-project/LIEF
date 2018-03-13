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
#include <iomanip>

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/DynamicSymbolCommand.hpp"

namespace LIEF {
namespace MachO {

DynamicSymbolCommand::DynamicSymbolCommand(void) :
  LoadCommand::LoadCommand{LOAD_COMMAND_TYPES::LC_DYSYMTAB, 0},
  idxLocalSymbol_{0},
  nbLocalSymbol_{0},
  idxExternalDefineSymbol_{0},
  nbExternalDefineSymbol_{0},
  idxUndefineSymbol_{0},
  nbUndefineSymbol_{0},
  tocOffset_{0},
  nbToc_{0},
  moduleTableOffset_{0},
  nbModuleTable_{0},
  externalReferenceSymbolOffset_{0},
  nbExternalReferenceSymbols_{0},
  indirectSymOffset_{0},
  nbIndirectSymbols_{0},
  externalRelocationOffset_{0},
  nbExternalRelocation_{0},
  localRelocationOffset_{0},
  nbLocRelocation_{0}
{}

DynamicSymbolCommand::DynamicSymbolCommand(const dysymtab_command *cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd->cmd), cmd->cmdsize},
  idxLocalSymbol_{cmd->ilocalsym},
  nbLocalSymbol_{cmd->nlocalsym},
  idxExternalDefineSymbol_{cmd->iextdefsym},
  nbExternalDefineSymbol_{cmd->nextdefsym},
  idxUndefineSymbol_{cmd->iundefsym},
  nbUndefineSymbol_{cmd->nundefsym},
  tocOffset_{cmd->tocoff},
  nbToc_{cmd->ntoc},
  moduleTableOffset_{cmd->modtaboff},
  nbModuleTable_{cmd->nmodtab},
  externalReferenceSymbolOffset_{cmd->extrefsymoff},
  nbExternalReferenceSymbols_{cmd->nextrefsyms},
  indirectSymOffset_{cmd->indirectsymoff},
  nbIndirectSymbols_{cmd->nindirectsyms},
  externalRelocationOffset_{cmd->extreloff},
  nbExternalRelocation_{cmd->nextrel},
  localRelocationOffset_{cmd->locreloff},
  nbLocRelocation_{cmd->nlocrel}
{}



DynamicSymbolCommand& DynamicSymbolCommand::operator=(const DynamicSymbolCommand&) = default;

DynamicSymbolCommand::DynamicSymbolCommand(const DynamicSymbolCommand&) = default;

DynamicSymbolCommand::~DynamicSymbolCommand(void) = default;


void DynamicSymbolCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool DynamicSymbolCommand::operator==(const DynamicSymbolCommand& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DynamicSymbolCommand::operator!=(const DynamicSymbolCommand& rhs) const {
  return not (*this == rhs);
}


std::ostream& DynamicSymbolCommand::print(std::ostream& os) const {

  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << std::setw(36) << "Local symbol index:"                << this->idxLocalSymbol_
     << std::endl
     << std::setw(36) << "Number of local symbols:"           << this->nbLocalSymbol_
     << std::endl
     << std::setw(36) << "External symbol index:"             << this->idxExternalDefineSymbol_
     << std::endl
     << std::setw(36) << "Number of external symbols:"        << this->nbExternalDefineSymbol_
     << std::endl
     << std::setw(36) << "Undefined symbol index:"            << this->idxUndefineSymbol_
     << std::endl
     << std::setw(36) << "Number of undefined symbols:"       << this->nbUndefineSymbol_
     << std::endl
     << std::setw(36) << "Table of content offset:"           << this->tocOffset_
     << std::endl
     << std::setw(36) << "Number of entries in TOC:"          << this->nbToc_
     << std::endl
     << std::setw(36) << "Module table offset:"               << this->moduleTableOffset_
     << std::endl
     << std::setw(36) << "Number of entries in module table:" << this->nbModuleTable_
     << std::endl
     << std::setw(36) << "External reference table offset:"   << this->externalReferenceSymbolOffset_
     << std::endl
     << std::setw(36) << "Number of external reference:"      << this->nbExternalReferenceSymbols_
     << std::endl
     << std::setw(36) << "Indirect symbols offset:"           << this->indirectSymOffset_
     << std::endl
     << std::setw(36) << "Number of indirect symbols:"        << this->nbIndirectSymbols_
     << std::endl
     << std::setw(36) << "External relocation offset:"        << this->externalRelocationOffset_
     << std::endl
     << std::setw(36) << "Local relocation offset:"           << this->localRelocationOffset_
     << std::endl
     << std::setw(36) << "Number of local relocations:"       << this->nbLocRelocation_
     << std::endl;

  return os;
}

}
}

