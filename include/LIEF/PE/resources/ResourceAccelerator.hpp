/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
 * Copyright 2017 - 2021 K. Nakagawa
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
#ifndef LIEF_PE_RESOURCE_ACCELERATOR_H
#define LIEF_PE_RESOURCE_ACCELERATOR_H

#include <string>
#include <set>
#include <ostream>

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"

#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {
class ResourcesManager;

namespace details {
struct pe_resource_acceltableentry;
}

class LIEF_API ResourceAccelerator : public Object {

  friend class ResourcesManager;

  public:
  ResourceAccelerator() = default;
  explicit ResourceAccelerator(const details::pe_resource_acceltableentry&);

  ResourceAccelerator(const ResourceAccelerator&) = default;
  ResourceAccelerator& operator=(const ResourceAccelerator&) = default;

  ~ResourceAccelerator() override = default;

  std::set<ACCELERATOR_FLAGS> flags_list() const;
  std::string ansi_str() const;

  //! Describe the keyboard accelerator characteristics
  int16_t flags() const {
    return flags_;
  }

  //! An ANSI character value or a virtual-key code that identifies the accelerator key
  int16_t ansi() const {
    return ansi_;
  }

  //! An identifier for the keyboard accelerator
  uint16_t id() const {
    return id_;
  }

  //! The number of bytes inserted to ensure that the structure is aligned on a DWORD boundary.
  int16_t padding() const {
    return padding_;
  }

  void accept(Visitor& visitor) const override;


  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceAccelerator& acc);

  private:
  int16_t flags_ = 0;
  int16_t ansi_ = 0;
  uint16_t id_ = 0;
  int16_t padding_ = 0;

};

}
}

#endif
