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
#include <iomanip>
#include <numeric>
#include <sstream>

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/SysvHash.hpp"

namespace LIEF {
namespace ELF {
SysvHash& SysvHash::operator=(const SysvHash&) = default;
SysvHash::SysvHash(const SysvHash&)            = default;
SysvHash::~SysvHash()                          = default;
SysvHash::SysvHash()                           = default;
SysvHash& SysvHash::operator=(SysvHash&&)      = default;
SysvHash::SysvHash(SysvHash&&)                 = default;


uint32_t SysvHash::nbucket() const {
  return static_cast<uint32_t>(buckets_.size());
}

uint32_t SysvHash::nchain() const {
  return static_cast<uint32_t>(chains_.size());
}

const std::vector<uint32_t>& SysvHash::buckets() const {
  return buckets_;
}

const std::vector<uint32_t>& SysvHash::chains() const {
  return chains_;
}

bool SysvHash::operator==(const SysvHash& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SysvHash::operator!=(const SysvHash& rhs) const {
  return !(*this == rhs);
}


void SysvHash::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


std::ostream& operator<<(std::ostream& os, const SysvHash& sysvhash) {
  os << std::hex << std::left;

  const std::vector<uint32_t>& buckets = sysvhash.buckets();
  const std::vector<uint32_t>& chains  = sysvhash.chains();

  std::string buckets_str = std::accumulate(
      std::begin(buckets),
      std::end(buckets), std::string{},
      [] (const std::string& a, uint32_t b) {
        std::ostringstream dec_bucket;
        dec_bucket << std::dec;
        dec_bucket << b;

        return a.empty() ? "[" + dec_bucket.str() : a + ", " + dec_bucket.str();
      });
  buckets_str += "]";


  std::string chains_str = std::accumulate(
      std::begin(chains),
      std::end(chains), std::string{},
      [] (const std::string& a, uint32_t b) {
        std::ostringstream dec_bucket;
        dec_bucket << std::dec;
        dec_bucket << b;

        return a.empty() ? "[" + dec_bucket.str() : a + ", " + dec_bucket.str();
      });
  buckets_str += "]";



  os << std::setw(33) << std::setfill(' ') << "Number of buckets:"  << sysvhash.nbucket() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Buckets:"            << buckets_str        << std::endl;

  os << std::setw(33) << std::setfill(' ') << "Number of chains:"   << sysvhash.nchain() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Chains:"             << chains_str        << std::endl;

  return os;

}

} // namespace ELF
} // namespace LIEF
