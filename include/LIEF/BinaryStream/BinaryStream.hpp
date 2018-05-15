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
#include <memory>

#include "LIEF/BinaryStream/Convert.hpp"

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

  std::string read_mutf8(size_t maxsize = -1ull) const;

  std::u16string read_u16string(size_t length) const;
  std::u16string peek_u16string(size_t length) const;
  std::u16string peek_u16string_at(size_t offset, size_t length) const;

  void setpos(size_t pos) const;
  void increment_pos(size_t value) const;
  size_t pos(void) const;

  operator bool() const;

  template<class T>
  const T* read_array(size_t size, bool check = true) const;

  template<class T>
  const T& peek(void) const;

  template<class T>
  const T& peek(size_t offset) const;

  template<class T>
  const T* peek_array(size_t size, bool check = true) const;

  template<class T>
  const T* peek_array(size_t offset, size_t size, bool check = true) const;

  template<class T>
  const T& read(void) const;

  template<typename T>
  static T swap_endian(T u);

  template<typename T>
  bool can_read(void) const;

  template<typename T>
  bool can_read(size_t offset) const;

  size_t align(size_t align_on) const;

  /* Read an integer value and adjust endianness as needed */
  template<typename T>
  T read_conv() const;

  /* Read an array of values and adjust endianness as needed */
  template<typename T>
  std::unique_ptr<T[]> read_conv_array(size_t size, bool check = true) const;

  template<typename T>
  T peek_conv(size_t offset) const;

  template<typename T>
  std::unique_ptr<T[]> peek_conv_array(size_t offset, size_t size, bool check = true) const;

  void set_endian_swap(bool swap);

  protected:
  virtual const void* read_at(uint64_t offset, uint64_t size, bool throw_error = true) const = 0;
  mutable size_t pos_{0};
  bool endian_swap_{false};
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
  const void* raw = this->read_at(this->pos(), sizeof(T), /* throw error*/ true);
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
const T* BinaryStream::peek_array(size_t size, bool check) const {
  const void* raw = this->read_at(this->pos(), sizeof(T) * size, /* throw error*/ check);
  return reinterpret_cast<const T*>(raw);
}

template<class T>
const T* BinaryStream::peek_array(size_t offset, size_t size, bool check) const {
  size_t saved_offset = this->pos();
  this->setpos(offset);
  const T* r = this->peek_array<T>(size, check);
  this->setpos(saved_offset);
  return r;
}


template<typename T>
bool BinaryStream::can_read(void) const {
  const void* raw = this->read_at(this->pos_, sizeof(T), /* throw error*/ false);
  return raw != nullptr;
}


template<typename T>
bool BinaryStream::can_read(size_t offset) const {
  const void* raw = this->read_at(offset, sizeof(T), /* throw error*/ false);
  return raw != nullptr;
}


template<class T>
const T* BinaryStream::read_array(size_t size, bool check) const {
  const T* tmp = this->peek_array<T>(size, check);
  this->increment_pos(sizeof(T) * size);
  return tmp;
}


template<typename T>
T BinaryStream::read_conv(void) const {
  T t = this->read<T>();
  if (this->endian_swap_) {
    LIEF::Convert::swap_endian<T>(& t);
  }
  return t;
}


template<typename T>
std::unique_ptr<T[]> BinaryStream::read_conv_array(size_t size, bool check) const {
  const T *t = this->read_array<T>(size, check);

  if (t == nullptr) {
	  return nullptr;
  }

  std::unique_ptr<T[]> uptr(new T[size]);

  for (size_t i = 0; i < size; i++) {
    uptr[i] = t[i];
    if (this->endian_swap_) {
        LIEF::Convert::swap_endian<T>(& uptr[i]);
    } /* else no conversion, just provide the copied data */
  }
  return uptr;
}

template<class T>
T BinaryStream::peek_conv(size_t offset) const {
  T t = this->peek<T>(offset);

  if (this->endian_swap_) {
    LIEF::Convert::swap_endian(&t);
  }
  return t;
}

template<typename T>
std::unique_ptr<T[]> BinaryStream::peek_conv_array(size_t offset, size_t size, bool check) const {
  const T *t = this->peek_array<T>(offset, size, check);

  if (t == nullptr) {
	  return nullptr;
  }

  std::unique_ptr<T[]> uptr(new T[size]);

  for (size_t i = 0; i < size; i++) {
    uptr[i] = t[i];
    if (this->endian_swap_) {
      LIEF::Convert::swap_endian<T>(& uptr[i]);
    } /* else no conversion, just provide the copied data */
  }
  return uptr;
}

#endif
