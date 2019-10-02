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
#ifndef LIEF_MACHO_CODE_DIRECTORY_H_
#define LIEF_MACHO_CODE_DIRECTORY_H_
#include "LIEF/Object.hpp"

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"


namespace LIEF {
namespace MachO {

class BinaryParser;

class LIEF_API CodeDirectory : public Object {
  friend class BinaryParser;
  public:
  // TODO: Expose API

  //bool operator==(const SubFramework& rhs) const;
  //bool operator!=(const SubFramework& rhs) const;

  //virtual void accept(Visitor& visitor) const override;

  //virtual std::ostream& print(std::ostream& os) const override;

  private:
  uint32_t version_;
  uint32_t flags_;
  uint32_t hash_offset_;
  uint32_t ident_offset_;
  uint32_t nb_special_slots_;
  uint32_t nb_code_slots_;
  uint32_t code_limit_;

  uint8_t hash_size_;
  uint8_t hash_type_;
  uint8_t reserved1_;
  uint8_t page_size_;
  uint32_t reserverd2_;
  uint32_t scatter_offset_;

};

}
}
#endif
