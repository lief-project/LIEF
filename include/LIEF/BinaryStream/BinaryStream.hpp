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
#ifndef LIEF_BINARY_STREAM_H_
#define LIEF_BINARY_STREAM_H_

#include <cstdint>
#include <climits>
#include <vector>
#include <istream>
#include <utility>
#include <memory>
#include <algorithm>

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
    VECTOR,
    MEMORY,
    SPAN,
    FILE,

    ELF_DATA_HANDLER,
  };

  BinaryStream();
  virtual ~BinaryStream();
  virtual uint64_t size() const = 0;

  inline STREAM_TYPE type() const {
    return stype_;
  }

  result<uint64_t> read_uleb128() const;
  result<uint64_t> read_sleb128() const;

  result<int64_t> read_dwarf_encoded(uint8_t encoding) const;

  result<std::string> read_string(size_t maxsize = ~static_cast<size_t>(0)) const;
  result<std::string> peek_string(size_t maxsize = ~static_cast<size_t>(0)) const;
  result<std::string> peek_string_at(size_t offset, size_t maxsize = ~static_cast<size_t>(0)) const;

  result<std::u16string> read_u16string() const;
  result<std::u16string> peek_u16string() const;

  result<std::string> read_mutf8(size_t maxsize = ~static_cast<size_t>(0)) const;

  result<std::u16string> read_u16string(size_t length) const;
  result<std::u16string> peek_u16string(size_t length) const;
  result<std::u16string> peek_u16string_at(size_t offset, size_t length) const;


  virtual inline ok_error_t peek_data(std::vector<uint8_t>& container,
                                      uint64_t offset, uint64_t size)
  {

    if (size == 0) {
      return ok();
    }
    // Even though offset + size < ... => offset < ...
    // the addition could overflow so it's worth checking both
    const bool read_ok = offset <= this->size() && (offset + size) <= this->size();
    if (!read_ok) {
      return make_error_code(lief_errors::read_error);
    }
    container.resize(size);
    if (peek_in(container.data(), offset, size)) {
      return ok();
    }
    return make_error_code(lief_errors::read_error);
  }

  virtual inline ok_error_t read_data(std::vector<uint8_t>& container, uint64_t size) {
    if (!peek_data(container, pos(), size)) {
      return make_error_code(lief_errors::read_error);
    }

    increment_pos(size);
    return ok();
  }

  void setpos(size_t pos) const;
  void increment_pos(size_t value) const;
  void decrement_pos(size_t value) const;
  size_t pos() const;

  operator bool() const;

  template<class T>
  const T* read_array(size_t size) const;

  template<class T>
  result<T> peek() const;

  template<class T>
  result<T> peek(size_t offset) const;

  template<class T>
  const T* peek_array(size_t size) const;

  template<class T>
  const T* peek_array(size_t offset, size_t size) const;

  template<class T>
  result<T> read() const;

  template<typename T>
  bool can_read() const;

  template<typename T>
  bool can_read(size_t offset) const;

  size_t align(size_t align_on) const;

  /* Functions that are endianness aware */
  template<class T>
  typename std::enable_if<std::is_integral<T>::value, result<T>>::type peek_conv() const;

  template<class T>
  typename std::enable_if<!std::is_integral<T>::value, result<T>>::type peek_conv() const;

  template<class T>
  result<T> peek_conv(size_t offset) const;

  template<class T>
  result<T> read_conv() const;

  /* Read an array of values and adjust endianness as needed */
  template<typename T>
  std::unique_ptr<T[]> read_conv_array(size_t size) const;

  template<typename T>
  std::unique_ptr<T[]> peek_conv_array(size_t offset, size_t size) const;

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


  template<class T>
  static bool is_all_zero(const T& buffer) {
    const auto* ptr = reinterpret_cast<const uint8_t *const>(&buffer);
    return std::all_of(ptr, ptr + sizeof(T),
                       [] (uint8_t x) { return x == 0; });
  }

  inline bool should_swap() const {
    return endian_swap_;
  }

  protected:
  virtual result<const void*> read_at(uint64_t offset, uint64_t size) const = 0;
  inline virtual ok_error_t peek_in(void* dst, uint64_t offset, uint64_t size) const {
    if (auto raw = read_at(offset, size)) {
      if (dst == nullptr) {
        return make_error_code(lief_errors::read_error);
      }
      const void* ptr = *raw;
      memcpy(dst, ptr, size);
      return ok();
    }
    return make_error_code(lief_errors::read_error);
  }
  mutable size_t pos_ = 0;
  bool endian_swap_ = false;
  STREAM_TYPE stype_ = STREAM_TYPE::UNKNOWN;
};

class ScopedStream {
  public:
  ScopedStream(const ScopedStream&) = delete;
  ScopedStream& operator=(const ScopedStream&) = delete;

  ScopedStream(const ScopedStream&&) = delete;
  ScopedStream& operator=(ScopedStream&&) = delete;

  explicit ScopedStream(BinaryStream& stream, uint64_t pos) :
    pos_{stream.pos()},
    stream_{stream}
  {
    stream_.setpos(pos);
  }

  inline ~ScopedStream() {
    stream_.setpos(pos_);
  }

  private:
  uint64_t pos_ = 0;
  BinaryStream& stream_;
};


template<class T>
result<T> BinaryStream::read() const {
  result<T> tmp = this->peek<T>();
  if (!tmp) {
    return tmp.error();
  }
  this->increment_pos(sizeof(T));
  return tmp;
}

template<class T>
result<T> BinaryStream::peek() const {
  const auto current_p = pos();
  T ret;
  if (auto res = peek_in(&ret, pos(), sizeof(T))) {
    setpos(current_p);
    return ret;
  }

  setpos(current_p);
  return make_error_code(lief_errors::read_error);
}

template<class T>
result<T> BinaryStream::peek(size_t offset) const {
  size_t saved_offset = this->pos();
  this->setpos(offset);
  result<T> r = this->peek<T>();
  this->setpos(saved_offset);
  return r;
}


template<class T>
const T* BinaryStream::peek_array(size_t size) const {
  result<const void*> raw = this->read_at(this->pos(), sizeof(T) * size);
  if (!raw) {
    return nullptr;
  }
  return reinterpret_cast<const T*>(raw.value());
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
bool BinaryStream::can_read() const {
  // Even though pos_ + sizeof(T) < ... => pos_ < ...
  // the addition could overflow so it's worth checking both
  return pos_ < size() && (pos_ + sizeof(T)) < size();
}


template<typename T>
bool BinaryStream::can_read(size_t offset) const {
  // Even though offset + sizeof(T) < ... => offset < ...
  // the addition could overflow so it's worth checking both
  return offset < size() && (offset + sizeof(T)) < size();
}


template<class T>
const T* BinaryStream::read_array(size_t size) const {
  const T* tmp = this->peek_array<T>(size);
  this->increment_pos(sizeof(T) * size);
  return tmp;
}


template<class T>
result<T> BinaryStream::read_conv() const {
  result<T> tmp = this->peek_conv<T>();
  if (!tmp) {
    return tmp.error();
  }
  this->increment_pos(sizeof(T));
  return tmp;
}

template<class T>
typename std::enable_if<std::is_integral<T>::value, result<T>>::type BinaryStream::peek_conv() const {
  T ret;
  if (auto res = peek_in(&ret, pos(), sizeof(T))) {
    if (endian_swap_) {
      return swap_endian<T>(ret);
    }
    return ret;
  }
  return make_error_code(lief_errors::read_error);
}

template<class T>
typename std::enable_if<!std::is_integral<T>::value, result<T>>::type BinaryStream::peek_conv() const {
  T ret;
  if (auto res = peek_in(&ret, pos(), sizeof(T))) {
    if (endian_swap_) {
      LIEF::Convert::swap_endian<T>(&ret);
    }
    return ret;
  }
  return make_error_code(lief_errors::read_error);
}


template<class T>
result<T> BinaryStream::peek_conv(size_t offset) const {
  size_t saved_offset = this->pos();
  this->setpos(offset);
  result<T> r = this->peek_conv<T>();
  this->setpos(saved_offset);
  return r;
}


template<typename T>
std::unique_ptr<T[]> BinaryStream::read_conv_array(size_t size) const {
  const T *t = this->read_array<T>(size);

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
std::unique_ptr<T[]> BinaryStream::peek_conv_array(size_t offset, size_t size) const {
  const T *t = this->peek_array<T>(offset, size);

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
