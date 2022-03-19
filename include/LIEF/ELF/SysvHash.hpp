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
#ifndef LIEF_ELF_SYSV_HASH_H_
#define LIEF_ELF_SYSV_HASH_H_

#include <iostream>
#include <vector>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace ELF {

class Parser;
class Builder;
class Binary;

//! Class which represents the SYSV hash for the symbols
//! resolution.
//!
//! References:
//! - http://www.linker-aliens.org/blogs/ali/entry/gnu_hash_elf_sections/
//! - https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-48031.html
class LIEF_API SysvHash : public Object {
  friend class Parser;
  friend class Builder;
  friend class Binary;

 public:
  SysvHash();
  SysvHash& operator=(const SysvHash& copy);
  SysvHash(const SysvHash& copy);

  SysvHash& operator=(SysvHash&&);
  SysvHash(SysvHash&&);
  ~SysvHash() override;

  //! @brief Return the number of buckets used
  uint32_t nbucket() const;

  //! @brief Return the number of chain used
  uint32_t nchain() const;

  //! @brief Buckets values
  const std::vector<uint32_t>& buckets() const;

  //! @brief Chains values
  const std::vector<uint32_t>& chains() const;

  inline void nchain(uint32_t nb) { chains_.resize(nb); }

  bool operator==(const SysvHash& rhs) const;
  bool operator!=(const SysvHash& rhs) const;

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os,
                                           const SysvHash& sysvhash);

 private:
  std::vector<uint32_t> buckets_;
  std::vector<uint32_t> chains_;
};

}  // namespace ELF
}  // namespace LIEF

#endif
