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
#ifndef LIEF_PE_CODE_VIEW_PDB_H_
#define LIEF_PE_CODE_VIEW_PDB_H_
#include <array>
#include <set>
#include <functional>
#include <algorithm>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/CodeView.hpp"
#include "LIEF/PE/Structures.hpp"

namespace LIEF {
namespace PE {
class LIEF_API CodeViewPDB : public CodeView {
  public:
  using signature_t = std::array<uint8_t, 16>;

  CodeViewPDB(void);
  CodeViewPDB(CODE_VIEW_SIGNATURES cv_signature, signature_t sig, uint32_t age, const std::string& filename);

  CodeViewPDB(const CodeViewPDB&);
  CodeViewPDB& operator=(const CodeViewPDB&);

  virtual CodeViewPDB* clone(void) const override;

  static CodeViewPDB from_pdb70(signature_t sig, uint32_t age, const std::string& filename);
  static CodeViewPDB from_pdb20(uint32_t signature, uint32_t age, const std::string& filename);

  signature_t signature(void) const;
  uint32_t age(void) const;
  const std::string& filename(void) const;

  void signature(uint32_t signature);
  void signature(signature_t signature);
  void age(uint32_t age);
  void filename(const std::string& filename);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const CodeViewPDB& rhs) const;
  bool operator!=(const CodeViewPDB& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const CodeViewPDB& entry);

  virtual ~CodeViewPDB(void);

  private:
  signature_t          signature_;
  uint32_t             age_;
  std::string          filename_;
};

} // Namespace PE
} // Namespace LIEF

#endif
