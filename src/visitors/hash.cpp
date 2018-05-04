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
#include <functional>
#include <numeric>

#include "mbedtls/sha256.h"

#include "LIEF/hash.hpp"


#if defined(LIEF_PE_SUPPORT)
#include "LIEF/PE/hash.hpp"
#endif

#if defined(LIEF_ELF_SUPPORT)
#include "LIEF/ELF/hash.hpp"
#endif

#if defined(LIEF_MACHO_SUPPORT)
#include "LIEF/MachO/hash.hpp"
#endif

#if defined(LIEF_OAT_SUPPORT)
#include "LIEF/OAT/hash.hpp"
#endif

#if defined(LIEF_ART_SUPPORT)
#include "LIEF/ART/hash.hpp"
#endif

#if defined(LIEF_DEX_SUPPORT)
#include "LIEF/DEX/hash.hpp"
#endif

#if defined(LIEF_VDEX_SUPPORT)
#include "LIEF/VDEX/hash.hpp"
#endif

namespace LIEF {

size_t hash(const Object& v) {
  size_t value = 0;

#if defined(LIEF_PE_SUPPORT)
  value = Hash::combine(value, Hash::hash<PE::Hash>(v));
#endif

#if defined(LIEF_ELF_SUPPORT)
  value = Hash::combine(value, Hash::hash<ELF::Hash>(v));
#endif

#if defined(LIEF_MACHO_SUPPORT)
  value = Hash::combine(value, Hash::hash<MachO::Hash>(v));
#endif

#if defined(LIEF_OAT_SUPPORT)
  value = Hash::combine(value, Hash::hash<OAT::Hash>(v));
#endif

#if defined(LIEF_ART_SUPPORT)
  value = Hash::combine(value, Hash::hash<ART::Hash>(v));
#endif

#if defined(LIEF_DEX_SUPPORT)
  value = Hash::combine(value, Hash::hash<DEX::Hash>(v));
#endif

#if defined(LIEF_VDEX_SUPPORT)
  value = Hash::combine(value, Hash::hash<VDEX::Hash>(v));
#endif

  return value;

}

size_t hash(const std::vector<uint8_t>& raw) {
  return Hash::hash(raw);
}

Hash::~Hash(void) = default;

Hash::Hash(void) :
  value_{0}
{}

Hash::Hash(size_t init_value) :
  value_{init_value}
{}


Hash& Hash::process(const Object& obj) {
  Hash hasher;
  obj.accept(hasher);
  this->value_ = combine(this->value_, hasher.value());
  return *this;
}

Hash& Hash::process(size_t integer) {
  this->value_ = combine(this->value_, std::hash<size_t>{}(integer));
  return *this;
}

Hash& Hash::process(const std::string& str) {
  this->value_ = combine(this->value_, std::hash<std::string>{}(str));
  return *this;
}


Hash& Hash::process(const std::u16string& str) {
  this->value_ = combine(this->value_, std::hash<std::u16string>{}(str));
  return *this;
}

Hash& Hash::process(const std::vector<uint8_t>& raw) {
  this->value_ = combine(this->value_, Hash::hash(raw));
  return *this;
}

size_t Hash::value(void) const {
  return this->value_;
}


// Static methods
// ==============
size_t Hash::hash(const std::vector<uint8_t>& raw) {
  std::vector<uint8_t> sha256(32, 0);
  mbedtls_sha256(raw.data(), raw.size(), sha256.data(), 0);

  return std::accumulate(
     std::begin(sha256),
     std::end(sha256), 0,
     [] (size_t v, uint8_t n) {
        size_t r = v;
        return (r << sizeof(uint8_t) * 8) | n;
     });
}


size_t Hash::hash(const void* raw, size_t size) {
  const uint8_t* start = reinterpret_cast<const uint8_t*>(raw);
  return Hash::hash(std::vector<uint8_t>{start, start + size});
}

}
