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
#include "LIEF/ELF/GnuHash.hpp"

#include <iomanip>
#include <numeric>
#include <sstream>
#include <utility>

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/utils.hpp"

namespace LIEF {
namespace ELF {

GnuHash::GnuHash(GnuHash&&) = default;
GnuHash& GnuHash::operator=(GnuHash&&) = default;

GnuHash& GnuHash::operator=(const GnuHash&) = default;
GnuHash::GnuHash(const GnuHash&) = default;
GnuHash::~GnuHash() = default;
GnuHash::GnuHash() = default;

GnuHash::GnuHash(uint32_t symbol_idx, uint32_t shift2,
                 std::vector<uint64_t> bloom_filters,
                 std::vector<uint32_t> buckets,
                 std::vector<uint32_t> hash_values)
    : symbol_index_{symbol_idx},
      shift2_{shift2},
      bloom_filters_{std::move(bloom_filters)},
      buckets_{std::move(buckets)},
      hash_values_{std::move(hash_values)} {}

uint32_t GnuHash::nb_buckets() const {
  return static_cast<uint32_t>(buckets_.size());
}

uint32_t GnuHash::symbol_index() const { return symbol_index_; }

uint32_t GnuHash::maskwords() const { return bloom_filters_.size(); }

uint32_t GnuHash::shift2() const { return shift2_; }

const std::vector<uint64_t>& GnuHash::bloom_filters() const {
  return bloom_filters_;
}

const std::vector<uint32_t>& GnuHash::buckets() const { return buckets_; }

const std::vector<uint32_t>& GnuHash::hash_values() const {
  return hash_values_;
}

bool GnuHash::check_bloom_filter(uint32_t hash) const {
  const size_t C = c_;
  const uint32_t h1 = hash;
  const uint32_t h2 = hash >> shift2();

  const uint32_t n1 = (h1 / C) % maskwords();

  const uint32_t b1 = h1 % C;
  const uint32_t b2 = h2 % C;
  const uint64_t filter = bloom_filters()[n1];
  return ((filter >> b1) & (filter >> b2) & 1) != 0u;
}

bool GnuHash::check_bucket(uint32_t hash) const {
  return buckets()[hash % nb_buckets()] > 0;
}

bool GnuHash::check(const std::string& symbol_name) const {
  uint32_t hash = dl_new_hash(symbol_name.c_str());
  return check(hash);
}

bool GnuHash::check(uint32_t hash) const {
  if (!check_bloom_filter(hash)) {  // Bloom filter not passed
    return false;
  }

  if (!check_bucket(hash)) {  // hash buck not passed
    return false;
  }
  return true;
}

bool GnuHash::operator==(const GnuHash& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool GnuHash::operator!=(const GnuHash& rhs) const { return !(*this == rhs); }

void GnuHash::accept(Visitor& visitor) const { visitor.visit(*this); }

std::ostream& operator<<(std::ostream& os, const GnuHash& gnuhash) {
  os << std::hex << std::left;

  const std::vector<uint64_t>& bloom_filters = gnuhash.bloom_filters();
  const std::vector<uint32_t>& buckets = gnuhash.buckets();
  const std::vector<uint32_t>& hash_values = gnuhash.hash_values();

  std::string bloom_filters_str = std::accumulate(
      std::begin(bloom_filters), std::end(bloom_filters), std::string{},
      [](const std::string& a, uint64_t bf) {
        std::ostringstream hex_bf;
        hex_bf << std::hex;
        hex_bf << "0x" << bf;

        return a.empty() ? "[" + hex_bf.str() : a + ", " + hex_bf.str();
      });
  bloom_filters_str += "]";

  std::string buckets_str = std::accumulate(
      std::begin(buckets), std::end(buckets), std::string{},
      [](const std::string& a, uint32_t b) {
        std::ostringstream hex_bucket;
        hex_bucket << std::dec;
        hex_bucket << b;

        return a.empty() ? "[" + hex_bucket.str() : a + ", " + hex_bucket.str();
      });
  buckets_str += "]";

  std::string hash_values_str = std::accumulate(
      std::begin(hash_values), std::end(hash_values), std::string{},
      [](const std::string& a, uint64_t hv) {
        std::ostringstream hex_hv;
        hex_hv << std::hex;
        hex_hv << "0x" << hv;

        return a.empty() ? "[" + hex_hv.str() : a + ", " + hex_hv.str();
      });
  hash_values_str += "]";

  os << std::setw(33) << std::setfill(' ')
     << "Number of buckets:" << gnuhash.nb_buckets() << std::endl;
  os << std::setw(33) << std::setfill(' ')
     << "First symbol index:" << gnuhash.symbol_index() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Shift Count:" << gnuhash.shift2()
     << std::endl;
  os << std::setw(33) << std::setfill(' ')
     << "Bloom filters:" << bloom_filters_str << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Buckets:" << buckets_str
     << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Hash values:" << hash_values_str
     << std::endl;

  return os;
}

}  // namespace ELF
}  // namespace LIEF
