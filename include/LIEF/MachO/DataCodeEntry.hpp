
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
#ifndef LIEF_MACHO_DATA_CODE_ENTRY_H_
#define LIEF_MACHO_DATA_CODE_ENTRY_H_
#include <string>
#include <vector>
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/Object.hpp"

namespace LIEF {
namespace MachO {

//! Interface of an entry in DataInCode
class LIEF_API DataCodeEntry : public LIEF::Object {
  public:
  enum class TYPES {
    UNKNOWN           = 0,
    DATA              = 1,
    JUMP_TABLE_8      = 2,
    JUMP_TABLE_16     = 3,
    JUMP_TABLE_32     = 4,
    ABS_JUMP_TABLE_32 = 5,
  };

  public:
  DataCodeEntry(void);
  DataCodeEntry(uint32_t off, uint16_t length, TYPES type);
  DataCodeEntry(const data_in_code_entry* entry);

  DataCodeEntry& operator=(const DataCodeEntry&);
  DataCodeEntry(const DataCodeEntry&);

  //! Offset of the data
  uint32_t offset(void) const;

  //! Length of the data
  uint16_t length(void) const;

  // Type of the data
  TYPES type(void) const;

  void offset(uint32_t off);
  void length(uint16_t length);
  void type(TYPES type);

  virtual ~DataCodeEntry(void);

  bool operator==(const DataCodeEntry& rhs) const;
  bool operator!=(const DataCodeEntry& rhs) const;

  virtual void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const DataCodeEntry& entry);

  private:
  uint32_t offset_;
  uint16_t length_;
  TYPES type_;
};

}
}

#endif
