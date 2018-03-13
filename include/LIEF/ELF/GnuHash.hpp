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
#ifndef LIEF_ELF_GNU_HASH_H_
#define LIEF_ELF_GNU_HASH_H_

#include <vector>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace ELF {

class Parser;
class Builder;
class Binary;

class LIEF_API GnuHash : public Object {

  friend class Parser;
  friend class Builder;
  friend class Binary;

  public:
  GnuHash(void);
  GnuHash(uint32_t symbol_idx,
      uint32_t shift2,
      const std::vector<uint64_t>& bloom_filters,
      const std::vector<uint32_t>& buckets,
      const std::vector<uint32_t>& hash_values = {});


  GnuHash& operator=(const GnuHash& copy);
  GnuHash(const GnuHash& copy);
  virtual ~GnuHash(void);

  //! @brief Return the number of buckets
  //! @see GnuHash::buckets
  uint32_t nb_buckets(void) const;

  //! @brief Index of the first symbol in the dynamic
  //! symbols table which accessible with the hash table
  uint32_t symbol_index(void) const;

  //! @brief Shift count used in the bloom filter
  uint32_t shift2(void) const;

  //! @brief Number of bloom filters used.
  //! It must be a power of 2
  uint32_t maskwords(void) const;

  //! @brief Bloom filters
  const std::vector<uint64_t>& bloom_filters(void) const;

  //! @brief Hash buckets
  const std::vector<uint32_t>& buckets(void) const;

  //! @brief Hash values
  const std::vector<uint32_t>& hash_values(void) const;

  //! @brief Check if the given hash pass the bloom filter
  bool check_bloom_filter(uint32_t hash) const;

  //! @brief Check if the given hash pass the bucket filter
  bool check_bucket(uint32_t hash) const;

  //! @brief Check if the symbol *probably* exists. If
  //! the returned value is ``false`` you can assume at ``100%`` that
  //! the symbol with the given name doesn't exists. If ``true`` you can't
  //! do any assumption
  bool check(const std::string& symbol_name) const;

  //! @brief Check if the symbol associated with the given *probably* exists. If
  //! the returned value is ``false`` you can assume at ``100%`` that
  //! the symbol doesn't exists. If ``true`` you can't
  //! do any assumption
  bool check(uint32_t hash) const;

  bool operator==(const GnuHash& rhs) const;
  bool operator!=(const GnuHash& rhs) const;

  virtual void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const GnuHash& gnuhash);

  private:
  uint32_t symbol_index_;
  uint32_t shift2_;

  std::vector<uint64_t> bloom_filters_;
  std::vector<uint32_t> buckets_;
  std::vector<uint32_t> hash_values_;

  size_t c_;
};


} // namepsace ELF
} // namespace LIEF

#endif
