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
#ifndef LIEF_PE_AUXILIARY_SEC_DEF_H
#define LIEF_PE_AUXILIARY_SEC_DEF_H

#include <memory>

#include "LIEF/visibility.h"
#include "LIEF/PE/AuxiliarySymbol.hpp"

namespace LIEF {

namespace PE {

/// This auxiliary symbol exposes information about the associated section.
///
/// It **duplicates** some information that are provided in the section header
class LIEF_API AuxiliarySectionDefinition : public AuxiliarySymbol {
  public:
  LIEF_LOCAL static std::unique_ptr<AuxiliarySectionDefinition>
    parse(const std::vector<uint8_t>& payload);

  AuxiliarySectionDefinition() :
    AuxiliarySymbol(AuxiliarySymbol::TYPE::SEC_DEF)
  {}

  AuxiliarySectionDefinition(uint32_t length, uint16_t nb_relocs,
                             uint16_t nb_lines, uint32_t checksum,
                             uint16_t sec_idx, uint8_t selection) :
    AuxiliarySymbol(AuxiliarySymbol::TYPE::SEC_DEF),
    length_(length),
    nb_relocs_(nb_relocs),
    nb_lines_(nb_lines),
    checksum_(checksum),
    sec_idx_(sec_idx),
    selection_(selection)
  {}

  AuxiliarySectionDefinition(const AuxiliarySectionDefinition&) = default;
  AuxiliarySectionDefinition& operator=(const AuxiliarySectionDefinition&) = default;

  AuxiliarySectionDefinition(AuxiliarySectionDefinition&&) = default;
  AuxiliarySectionDefinition& operator=(AuxiliarySectionDefinition&&) = default;

  std::unique_ptr<AuxiliarySymbol> clone() const override {
    return std::unique_ptr<AuxiliarySectionDefinition>(new AuxiliarySectionDefinition{*this});
  }

  /// The size of section data. The same as `SizeOfRawData` in the section header.
  uint32_t length() const {
    return length_;
  }

  /// The number of relocation entries for the section.
  uint16_t nb_relocs() const {
    return nb_relocs_;
  }

  /// The number of line-number entries for the section.
  uint16_t nb_line_numbers() const {
    return nb_lines_;
  }

  /// The checksum for communal data. It is applicable if the
  /// `IMAGE_SCN_LNK_COMDAT` flag is set in the section header.
  uint32_t checksum() const {
    return checksum_;
  }

  /// One-based index into the section table for the associated section.
  /// This is used when the COMDAT selection setting is 5.
  uint16_t section_idx() const {
    return sec_idx_;
  }

  /// The COMDAT selection number. This is applicable if the section is a
  /// COMDAT section.
  uint8_t selection() const {
    return selection_;
  }

  std::string to_string() const override;

  static bool classof(const AuxiliarySymbol* sym) {
    return sym->type() == AuxiliarySymbol::TYPE::SEC_DEF;
  }

  ~AuxiliarySectionDefinition() override = default;

  private:
  uint32_t length_ = 0;
  uint16_t nb_relocs_ = 0;
  uint16_t nb_lines_ = 0;
  uint32_t checksum_ = 0;
  uint16_t sec_idx_ = 0;
  uint8_t selection_ = 0;
};

}
}
#endif
