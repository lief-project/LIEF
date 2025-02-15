/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#ifndef LIEF_PE_AUXILIARY_CLR_TOKEN_H
#define LIEF_PE_AUXILIARY_CLR_TOKEN_H

#include <memory>

#include "LIEF/visibility.h"
#include "LIEF/PE/AuxiliarySymbol.hpp"

namespace LIEF {

namespace PE {

class LIEF_API AuxiliaryCLRToken : public AuxiliarySymbol {
  public:
  LIEF_LOCAL static std::unique_ptr<AuxiliaryCLRToken>
    parse(const std::vector<uint8_t>& payload);

  AuxiliaryCLRToken() :
    AuxiliarySymbol(AuxiliarySymbol::TYPE::CLR_TOKEN)
  {}

  AuxiliaryCLRToken(const AuxiliaryCLRToken&) = default;
  AuxiliaryCLRToken& operator=(const AuxiliaryCLRToken&) = default;

  AuxiliaryCLRToken(AuxiliaryCLRToken&&) = default;
  AuxiliaryCLRToken& operator=(AuxiliaryCLRToken&&) = default;

  std::unique_ptr<AuxiliarySymbol> clone() const override {
    return std::unique_ptr<AuxiliaryCLRToken>(new AuxiliaryCLRToken{*this});
  }

  std::string to_string() const override {
    return "AuxiliaryCLRToken";
  }

  static bool classof(const AuxiliarySymbol* sym) {
    return sym->type() == AuxiliarySymbol::TYPE::CLR_TOKEN;
  }

  ~AuxiliaryCLRToken() override = default;
};

}
}
#endif
