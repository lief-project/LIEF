/* Copyright 2022 - 2024 R. Thomas
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
#ifndef LIEF_DEBUGINFO_H
#define LIEF_DEBUGINFO_H
#include <memory>
namespace LIEF {

namespace details {
class DebugInfo;
}

class DebugInfo {
  public:
  enum class FORMAT {
    UNKNOWN = 0,
    DWARF, PDB,
  };
  DebugInfo(std::unique_ptr<details::DebugInfo> impl);
  virtual ~DebugInfo();

  virtual FORMAT format() const {
    return FORMAT::UNKNOWN;
  }

  protected:
  std::unique_ptr<details::DebugInfo> impl_;
};

}
#endif
