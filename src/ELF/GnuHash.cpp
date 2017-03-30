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
#include <iomanip>
#include <numeric>
#include <sstream>

#include "LIEF/ELF/GnuHash.hpp"

namespace LIEF {
namespace ELF {
GnuHash& GnuHash::operator=(const GnuHash&) = default;
GnuHash::GnuHash(const GnuHash&)           = default;
GnuHash::~GnuHash(void)                    = default;

GnuHash::GnuHash(void) :
  symbol_index_{0},
  shift2_{0},
  bloom_filters_{0},
  buckets_{0},
  hash_values_{0}
{}


uint32_t GnuHash::nb_buckets(void) const {
  return static_cast<uint32_t>(this->buckets_.size());
}

uint32_t GnuHash::symbol_index(void) const {
  return this->symbol_index_;
}


uint32_t GnuHash::maskwords(void) const {
  return this->bloom_filters_.size();
}

uint32_t GnuHash::shift2(void) const {
  return this->shift2_;
}

const std::vector<uint64_t>& GnuHash::bloom_filters(void) const {
  return this->bloom_filters_;
}

const std::vector<uint32_t>& GnuHash::buckets(void) const {
  return this->buckets_;
}

const std::vector<uint32_t>& GnuHash::hash_values(void) const {
  return this->hash_values_;
}

void GnuHash::accept(Visitor&) const {

}


std::ostream& operator<<(std::ostream& os, const GnuHash& gnuhash) {
  os << std::hex << std::left;

  const std::vector<uint64_t>& bloom_filters = gnuhash.bloom_filters();
  const std::vector<uint32_t>& buckets       = gnuhash.buckets();
  const std::vector<uint32_t>& hash_values   = gnuhash.hash_values();

  std::string bloom_filters_str = std::accumulate(
      std::begin(bloom_filters),
      std::end(bloom_filters), std::string{},
      [] (const std::string& a, uint64_t bf) {
        std::ostringstream hex_bf;
        hex_bf << std::hex;
        hex_bf << "0x" << bf;

        return a.empty() ? "[" + hex_bf.str() : a + ", " + hex_bf.str();
      });
  bloom_filters_str += "]";

  std::string buckets_str = std::accumulate(
      std::begin(buckets),
      std::end(buckets), std::string{},
      [] (const std::string& a, uint32_t b) {
        std::ostringstream hex_bucket;
        hex_bucket << std::dec;
        hex_bucket  << b;

        return a.empty() ? "[" + hex_bucket.str() : a + ", " + hex_bucket.str();
      });
  buckets_str += "]";


  std::string hash_values_str = std::accumulate(
      std::begin(hash_values),
      std::end(hash_values), std::string{},
      [] (const std::string& a, uint64_t hv) {
        std::ostringstream hex_hv;
        hex_hv << std::hex;
        hex_hv << "0x" << hv;

        return a.empty() ? "[" + hex_hv.str() : a + ", " + hex_hv.str();
      });
  hash_values_str += "]";

  os << std::setw(33) << std::setfill(' ') << "Number of buckets:"  << gnuhash.nb_buckets()   << std::endl;
  os << std::setw(33) << std::setfill(' ') << "First symbol index:" << gnuhash.symbol_index() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Shift Count:"        << gnuhash.shift2()       << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Bloom filters:"      << bloom_filters_str      << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Buckets:"            << buckets_str            << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Hash values:"        << hash_values_str        << std::endl;




  return os;

}

} // namespace ELF
} // namespace LIEF
