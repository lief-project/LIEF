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
#ifndef LIEF_PE_CODE_INTEGRITY_H_
#define LIEF_PE_CODE_INTEGRITY_H_
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace PE {
namespace details {
struct pe_code_integrity;
}

class LIEF_API CodeIntegrity : public Object {
 public:
  static constexpr size_t PRINT_WIDTH = 20;
  CodeIntegrity();
  CodeIntegrity(const details::pe_code_integrity& header);
  virtual ~CodeIntegrity();

  CodeIntegrity& operator=(const CodeIntegrity&);
  CodeIntegrity(const CodeIntegrity&);

  //! Flags to indicate if CI information is available, etc.
  uint16_t flags() const;

  //! 0xFFFF means not available
  uint16_t catalog() const;
  uint32_t catalog_offset() const;

  //! Additional bitmask to be defined later
  uint32_t reserved() const;

  void flags(uint16_t flags);
  void catalog(uint16_t catalog);
  void catalog_offset(uint32_t catalog_offset);
  void reserved(uint32_t reserved);

  void accept(Visitor& visitor) const override;

  bool operator==(const CodeIntegrity& rhs) const;
  bool operator!=(const CodeIntegrity& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os,
                                           const CodeIntegrity& entry);

 private:
  uint16_t flags_;
  uint16_t catalog_;

  uint32_t catalog_offset_;
  uint32_t reserved_;
};
}  // namespace PE
}  // namespace LIEF

#endif
