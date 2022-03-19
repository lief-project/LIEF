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
#ifndef LIEF_MACHO_DATA_CODE_ENTRY_H_
#define LIEF_MACHO_DATA_CODE_ENTRY_H_
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace MachO {

namespace details {
struct data_in_code_entry;
}

//! Interface over an entry in the DataInCode command
class LIEF_API DataCodeEntry : public LIEF::Object {
 public:
  enum class TYPES {
    UNKNOWN = 0,
    DATA = 1,
    JUMP_TABLE_8 = 2,
    JUMP_TABLE_16 = 3,
    JUMP_TABLE_32 = 4,
    ABS_JUMP_TABLE_32 = 5,
  };

 public:
  DataCodeEntry();
  DataCodeEntry(uint32_t off, uint16_t length, TYPES type);
  DataCodeEntry(const details::data_in_code_entry& entry);

  DataCodeEntry& operator=(const DataCodeEntry&);
  DataCodeEntry(const DataCodeEntry&);

  //! Offset of the data
  uint32_t offset() const;

  //! Length of the data
  uint16_t length() const;

  // Type of the data
  TYPES type() const;

  void offset(uint32_t off);
  void length(uint16_t length);
  void type(TYPES type);

  virtual ~DataCodeEntry();

  bool operator==(const DataCodeEntry& rhs) const;
  bool operator!=(const DataCodeEntry& rhs) const;

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os,
                                           const DataCodeEntry& entry);

 private:
  uint32_t offset_;
  uint16_t length_;
  TYPES type_;
};

}  // namespace MachO
}  // namespace LIEF

#endif
