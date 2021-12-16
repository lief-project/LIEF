/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#ifndef LIEF_MACHO_SEGMENT_SPLIT_INFO_H_
#define LIEF_MACHO_SEGMENT_SPLIT_INFO_H_
#include <vector>
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {
class BinaryParser;

struct linkedit_data_command;

class LIEF_API SegmentSplitInfo : public LoadCommand {
  friend class BinaryParser;
  public:
  SegmentSplitInfo();
  SegmentSplitInfo(const linkedit_data_command *cmd);

  SegmentSplitInfo& operator=(const SegmentSplitInfo& copy);
  SegmentSplitInfo(const SegmentSplitInfo& copy);

  virtual SegmentSplitInfo* clone() const override;

  uint32_t data_offset() const;
  uint32_t data_size() const;

  void data_offset(uint32_t offset);
  void data_size(uint32_t size);

  virtual ~SegmentSplitInfo();

  bool operator==(const SegmentSplitInfo& rhs) const;
  bool operator!=(const SegmentSplitInfo& rhs) const;

  virtual void accept(Visitor& visitor) const override;

  virtual std::ostream& print(std::ostream& os) const override;

  private:
  uint32_t              data_offset_;
  uint32_t              data_size_;
  std::vector<uint8_t>  raw_;

};

}
}
#endif
