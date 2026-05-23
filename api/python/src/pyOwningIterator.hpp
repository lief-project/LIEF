/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#ifndef PY_LIEF_OWNING_ITERATOR_H
#define PY_LIEF_OWNING_ITERATOR_H

#include <iterator>
#include <memory>
#include <utility>

#include "LIEF/iterators.hpp"

namespace LIEF::py {

template<class It>
class OwningIterator {
  public:
  using underlying_type =
      typename std::iterator_traits<It>::value_type;

  using iterator_category = std::input_iterator_tag;
  using value_type = std::unique_ptr<underlying_type>;
  using difference_type = std::ptrdiff_t;
  using pointer = void;
  using reference = std::unique_ptr<underlying_type>;

  OwningIterator() = default;
  explicit OwningIterator(It it) :
    it_(std::move(it)) {}

  OwningIterator& operator=(const OwningIterator&) = default;
  OwningIterator(const OwningIterator&) = default;

  OwningIterator& operator=(OwningIterator&&) noexcept = default;
  OwningIterator(OwningIterator&&) noexcept = default;

  ~OwningIterator() = default;

  std::unique_ptr<underlying_type> operator*() {
    return it_.yield();
  }

  OwningIterator& operator++() {
    ++it_;
    return *this;
  }

  OwningIterator operator++(int) {
    OwningIterator tmp = *this;
    ++(*this);
    return tmp;
  }

  friend bool operator==(const OwningIterator& lhs, const OwningIterator& rhs) {
    return lhs.it_ == rhs.it_;
  }

  friend bool operator!=(const OwningIterator& lhs, const OwningIterator& rhs) {
    return !(lhs == rhs);
  }

  private:
  It it_;
};

template<class It>
iterator_range<OwningIterator<It>>
    owning_range(const iterator_range<It>& range) {
  return {
    OwningIterator<It>(std::move(range.begin())),
    OwningIterator<It>(std::move(range.end()))
  };
}

template<class It>
class OwningRandomAccessIterator {
  public:
  using underlying_type =
      typename std::iterator_traits<It>::value_type;

  using iterator_category = std::random_access_iterator_tag;
  using value_type = std::unique_ptr<underlying_type>;
  using difference_type = std::ptrdiff_t;
  using pointer = void;
  using reference = std::unique_ptr<underlying_type>;

  OwningRandomAccessIterator() = default;
  explicit OwningRandomAccessIterator(It it) :
    it_(std::move(it)) {}

  std::unique_ptr<underlying_type> operator*() const {
    It scratch = it_;
    return scratch.yield();
  }

  OwningRandomAccessIterator& operator++() {
    ++it_;
    return *this;
  }

  OwningRandomAccessIterator operator++(int) {
    OwningRandomAccessIterator tmp = *this;
    ++(*this);
    return tmp;
  }

  OwningRandomAccessIterator& operator--() {
    --it_;
    return *this;
  }

  OwningRandomAccessIterator operator--(int) {
    OwningRandomAccessIterator tmp = *this;
    --(*this);
    return tmp;
  }

  OwningRandomAccessIterator& operator+=(difference_type n) {
    it_ += n;
    return *this;
  }

  OwningRandomAccessIterator& operator-=(difference_type n) {
    it_ -= n;
    return *this;
  }

  OwningRandomAccessIterator operator+(difference_type n) const {
    OwningRandomAccessIterator tmp = *this;
    tmp += n;
    return tmp;
  }

  OwningRandomAccessIterator operator-(difference_type n) const {
    OwningRandomAccessIterator tmp = *this;
    tmp -= n;
    return tmp;
  }

  difference_type operator-(const OwningRandomAccessIterator& other) const {
    return it_ - other.it_;
  }

  friend bool operator==(const OwningRandomAccessIterator& lhs,
                         const OwningRandomAccessIterator& rhs) {
    return lhs.it_ == rhs.it_;
  }

  friend bool operator!=(const OwningRandomAccessIterator& lhs,
                         const OwningRandomAccessIterator& rhs) {
    return !(lhs == rhs);
  }

  friend bool operator<(const OwningRandomAccessIterator& lhs,
                        const OwningRandomAccessIterator& rhs) {
    return lhs.it_ < rhs.it_;
  }

  private:
  It it_;
};

template<class It>
iterator_range<OwningRandomAccessIterator<It>>
    owning_random_access_range(const iterator_range<It>& range) {
  return {OwningRandomAccessIterator<It>(range.begin()),
          OwningRandomAccessIterator<It>(range.end())};
}
}

#endif
