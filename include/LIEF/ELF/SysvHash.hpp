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
#ifndef LIEF_ELF_SYSV_HASH_H_
#define LIEF_ELF_SYSV_HASH_H_

#include <vector>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace ELF {

class Parser;
class Builder;
class Binary;

class LIEF_API SysvHash : public Object {

  friend class Parser;
  friend class Builder;
  friend class Binary;

  public:
  SysvHash(void);
  SysvHash& operator=(const SysvHash& copy);
  SysvHash(const SysvHash& copy);
  virtual ~SysvHash(void);

  //! @brief Return the number of buckets used
  uint32_t nbucket(void) const;

  //! @brief Return the number of chain used
  uint32_t nchain(void) const;

  //! @brief Buckets values
  const std::vector<uint32_t>& buckets(void) const;

  //! @brief Chains values
  const std::vector<uint32_t>& chains(void) const;

  bool operator==(const SysvHash& rhs) const;
  bool operator!=(const SysvHash& rhs) const;

  virtual void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const SysvHash& sysvhash);

  private:
  std::vector<uint32_t> buckets_;
  std::vector<uint32_t> chains_;

};


} // namepsace ELF
} // namespace LIEF

#endif
