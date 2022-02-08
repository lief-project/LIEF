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
#ifndef LIEF_HASH_STREAM_H_
#define LIEF_HASH_STREAM_H_
#include <vector>
#include <string>
#include <array>
#include <memory>

namespace LIEF {
class hashstream {
  public:
  enum class HASH {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512
  };
  hashstream(HASH type);

  hashstream& put(uint8_t c);
  hashstream& write(const uint8_t* s, size_t n);
  hashstream& write(const std::vector<uint8_t>& s);
  hashstream& write(const std::string& s);
  hashstream& write(size_t count, uint8_t value);
  hashstream& write_sized_int(uint64_t value, size_t size);

  template<typename T>
  hashstream& write_conv(const T& t);

  template<typename T>
  hashstream& write_conv_array(const std::vector<T>& v);

  hashstream& align(size_t size, uint8_t val = 0);

  template<class Integer, typename = typename std::enable_if<std::is_integral<Integer>::value>>
  hashstream& write(Integer integer) {
    const auto* int_p = reinterpret_cast<const uint8_t*>(&integer);
    return write(int_p, sizeof(Integer));
  }

  template<typename T, size_t size, typename = typename std::enable_if<std::is_integral<T>::value>>
  hashstream& write(const std::array<T, size>& t) {
    for (T val : t) {
      write<T>(val);
    }
    return *this;
  }

  hashstream& get(std::vector<uint8_t>& c);
  hashstream& flush();

  std::vector<uint8_t>& raw();
  ~hashstream();

  private:
  std::vector<uint8_t> output_;
  using md_context_t = intptr_t;
  std::unique_ptr<md_context_t> ctx_;
};


}
#endif
