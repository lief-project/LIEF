/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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

#include <cstdint>
#include <climits>
#include <vector>
#include <istream>
#include <utility>
#include <memory>

#include "LIEF/BinaryStream/Convert.hpp"
#include "LIEF/errors.hpp"

struct mbedtls_x509_crt;
struct mbedtls_x509_time;

namespace LIEF {


//! Class that is used to a read stream of data from different sources
class BinaryStream {
  public:
  enum class STREAM_TYPE {
    UNKNOWN = 0,
    FILE,
    MEMORY,
  };

  BinaryStream();
  virtual ~BinaryStream();
  virtual uint64_t size() const = 0;

  virtual STREAM_TYPE type() const = 0;

  uint64_t read_uleb128() const;
  uint64_t read_sleb128() const;

  int64_t read_dwarf_encoded(uint8_t encoding) const;

  std::string read_string(size_t maxsize = ~static_cast<size_t>(0)) const;
  std::string peek_string(size_t maxsize = ~static_cast<size_t>(0)) const;
  std::string peek_string_at(size_t offset, size_t maxsize = ~static_cast<size_t>(0)) const;

  std::u16string read_u16string() const;
  std::u16string peek_u16string() const;

  std::string read_mutf8(size_t maxsize = ~static_cast<size_t>(0)) const;

  std::u16string read_u16string(size_t length) const;
  std::u16string peek_u16string(size_t length) const;
  std::u16string peek_u16string_at(size_t offset, size_t length) const;

  void setpos(size_t pos) const;
  void increment_pos(size_t value) const;
  size_t pos() const;

  operator bool() const;

  template<class T>
  const T* read_array(size_t size, bool check = true) const;

  template<class T>
  typename std::enable_if<std::is_integral<T>::value, T>::type peek() const;

  template<class T>
  typename std::enable_if<!std::is_integral<T>::value, T>::type peek() const;

  template<class T>
  T peek(size_t offset) const;

  template<class T>
  const T* peek_array(size_t size, bool check = true) const;

  template<class T>
  const T* peek_array(size_t offset, size_t size, bool check = true) const;

  template<class T>
  T read() const;

  template<typename T>
  bool can_read() const;

  template<typename T>
  bool can_read(size_t offset) const;

  size_t align(size_t align_on) const;

  /* Functions that are endianness aware */
  template<class T>
  typename std::enable_if<std::is_integral<T>::value, T>::type peek_conv() const;

  template<class T>
  typename std::enable_if<!std::is_integral<T>::value, T>::type peek_conv() const;

  template<class T>
  T peek_conv(size_t offset) const;

  template<class T>
  T read_conv() const;

  /* Read an array of values and adjust endianness as needed */
  template<typename T>
  std::unique_ptr<T[]> read_conv_array(size_t size, bool check = true) const;

  template<typename T>
  std::unique_ptr<T[]> peek_conv_array(size_t offset, size_t size, bool check = true) const;

  template<typename T>
  static T swap_endian(T u);

  void set_endian_swap(bool swap);

  /* ASN.1 & X509 parsing functions */
  virtual result<size_t>                             asn1_read_tag(int tag);
  virtual result<size_t>                             asn1_read_len();
  virtual result<std::string>                        asn1_read_alg();
  virtual result<std::string>                        asn1_read_oid();
  virtual result<int32_t>                            asn1_read_int();
  virtual result<std::vector<uint8_t>>               asn1_read_bitstring();
  virtual result<std::vector<uint8_t>>               asn1_read_octet_string();
  virtual result<std::unique_ptr<mbedtls_x509_crt>>  asn1_read_cert();
  virtual result<std::string>                        x509_read_names();
  virtual result<std::vector<uint8_t>>               x509_read_serial();
  virtual result<std::unique_ptr<mbedtls_x509_time>> x509_read_time();

  protected:
  virtual const void* read_at(uint64_t offset, uint64_t size, bool throw_error = true) const = 0;
  mutable size_t pos_{0};
  bool endian_swap_{false};
};


template<class T>
T BinaryStream::read() const {
  T tmp = this->peek<T>();
  this->increment_pos(sizeof(T));
  return tmp;
}

template<class T>
typename std::enable_if<std::is_integral<T>::value, T>::type BinaryStream::peek() const {
  const void* raw = this->read_at(this->pos(), sizeof(T), /* throw error*/ true);
  T ret;
  memcpy(&ret, raw, sizeof(T));
  return ret;
}

template<class T>
typename std::enable_if<!std::is_integral<T>::value, T>::type BinaryStream::peek() const {
  const void* raw = this->read_at(this->pos(), sizeof(T), /* throw error*/ true);
  return *reinterpret_cast<const T*>(raw);
}


template<class T>
T BinaryStream::peek(size_t offset) const {
  size_t saved_offset = this->pos();
  this->setpos(offset);
  T r = this->peek<T>();
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
bool BinaryStream::can_read() const {
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


template<class T>
T BinaryStream::read_conv() const {
  T tmp = this->peek_conv<T>();
  this->increment_pos(sizeof(T));
  return tmp;
}

template<class T>
typename std::enable_if<std::is_integral<T>::value, T>::type BinaryStream::peek_conv() const {
  const void* raw = this->read_at(this->pos(), sizeof(T), /* throw error*/ true);
  T ret;
  memcpy(&ret, raw, sizeof(T));
  if (endian_swap_) {
    return swap_endian<T>(ret);
  }
  return ret;
}

template<class T>
typename std::enable_if<!std::is_integral<T>::value, T>::type BinaryStream::peek_conv() const {
  const void* raw = this->read_at(this->pos(), sizeof(T), /* throw error*/ true);
  T ret = *reinterpret_cast<const T*>(raw);
  if (endian_swap_) {
    LIEF::Convert::swap_endian<T>(&ret);
  }
  return ret;
}


template<class T>
T BinaryStream::peek_conv(size_t offset) const {
  size_t saved_offset = this->pos();
  this->setpos(offset);
  T r = this->peek_conv<T>();
  this->setpos(saved_offset);
  return r;
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
}
#endif
