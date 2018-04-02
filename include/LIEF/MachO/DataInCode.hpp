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
#ifndef LIEF_MACHO_DATA_IN_CODE_COMMAND_H_
#define LIEF_MACHO_DATA_IN_CODE_COMMAND_H_
#include <string>
#include <vector>
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/MachO/DataCodeEntry.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;

//! Interface of the LC_DATA_IN_CODE command
class LIEF_API DataInCode : public LoadCommand {
  friend class BinaryParser;
  public:
  using entries_t        = std::vector<DataCodeEntry>;
  using it_const_entries = const_ref_iterator<const entries_t&>;
  using it_entries       = ref_iterator<entries_t&>;

  public:
  DataInCode(void);
  DataInCode(const linkedit_data_command *cmd);

  DataInCode& operator=(const DataInCode&);
  DataInCode(const DataInCode&);

  uint32_t data_offset(void) const;
  uint32_t data_size(void) const;

  void data_offset(uint32_t offset);
  void data_size(uint32_t size);

  DataInCode& add(const DataCodeEntry& entry);

  it_const_entries entries(void) const;
  it_entries entries(void);

  virtual ~DataInCode(void);

  bool operator==(const DataInCode& rhs) const;
  bool operator!=(const DataInCode& rhs) const;

  virtual void accept(Visitor& visitor) const override;

  virtual std::ostream& print(std::ostream& os) const override;

  private:
  uint32_t  data_offset_;
  uint32_t  data_size_;
  entries_t entries_;

};

}
}
#endif
