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
#ifndef LIEF_BINARY_STREAM_H_
#define LIEF_BINARY_STREAM_H_

#include <stdint.h>
#include <climits>
#include <vector>
#include <istream>
#include <utility>

class BinaryStream {
  public:
  BinaryStream(void);
  virtual ~BinaryStream();
  virtual uint64_t size(void) const = 0;

  uint64_t read_uleb128(void) const;
  uint64_t read_sleb128(void) const;

  std::string read_string(size_t maxsize = -1u) const;
  std::string peek_string(size_t maxsize = -1u) const;
  std::string peek_string_at(size_t offset, size_t maxsize = -1u) const;

  std::u16string read_u16string(void) const;
  std::u16string peek_u16string(void) const;

  std::u16string read_u16string(size_t length) const;
  std::u16string peek_u16string(size_t length) const;
  std::u16string peek_u16string_at(size_t offset, size_t length) const;

  void setpos(size_t pos) const;
  void increment_pos(size_t value) const;
  size_t pos(void) const;

  operator bool() const;

  template<class T>
  const T* read_array(size_t size) const;

  template<class T>
  const T& peek(void) const;

  template<class T>
  const T& peek(size_t offset) const;

  template<class T>
  const T* peek_array(size_t size) const;

  template<class T>
  const T* peek_array(size_t offset, size_t size) const;

  template<class T>
  const T& read(void) const;

  template<typename T>
  static T swap_endian(T u);

  template<typename T>
  bool can_read(void) const;

  template<typename T>
  bool can_read(size_t offset) const;

  size_t align(size_t align_on) const;

  protected:
  virtual const void* read_at(uint64_t offset, uint64_t size) const = 0;
  mutable size_t pos_{0};
};


template<typename T>
T BinaryStream::swap_endian(T u) {
  // From http://stackoverflow.com/a/4956493
  static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");
  static_assert(std::is_integral<T>::value, "Interger required");
  union {
    T u;
    unsigned char u8[sizeof(T)];
  } source, dest;

  source.u = u;

  for (size_t k = 0; k < sizeof(T); k++) {
    dest.u8[k] = source.u8[sizeof(T) - k - 1];
  }

  return dest.u;
}


template<class T>
const T& BinaryStream::read(void) const {
  const T& tmp = this->peek<T>();
  this->increment_pos(sizeof(T));
  return tmp;
}

template<class T>
const T& BinaryStream::peek(void) const {
  const void* raw = this->read_at(this->pos(), sizeof(T));
  return *reinterpret_cast<const T*>(raw);
}


template<class T>
const T& BinaryStream::peek(size_t offset) const {
  size_t saved_offset = this->pos();
  this->setpos(offset);
  const T& r = this->peek<T>();
  this->setpos(saved_offset);
  return r;
}


template<class T>
const T* BinaryStream::peek_array(size_t size) const {
  const void* raw = this->read_at(this->pos(), sizeof(T) * size);
  return reinterpret_cast<const T*>(raw);
}

template<class T>
const T* BinaryStream::peek_array(size_t offset, size_t size) const {
  size_t saved_offset = this->pos();
  this->setpos(offset);
  const T* r = this->peek_array<T>(size);
  this->setpos(saved_offset);
  return r;
}


template<typename T>
bool BinaryStream::can_read(void) const {
  const void* raw = this->read_at(this->pos_, sizeof(T));
  return raw != nullptr;
}


template<typename T>
bool BinaryStream::can_read(size_t offset) const {
  const void* raw = this->read_at(offset, sizeof(T));
  return raw != nullptr;
}


template<class T>
const T* BinaryStream::read_array(size_t size) const {
  const T* tmp = this->peek_array<T>(size);
  this->increment_pos(sizeof(T) * size);
  return tmp;
}



#endif
