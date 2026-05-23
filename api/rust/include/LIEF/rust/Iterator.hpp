/* Copyright 2024 - 2026 R. Thomas
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
#pragma once
#include <cstdint>
#include <memory>
#include <type_traits>
#include "LIEF/iterators.hpp"

namespace details {
template<class It, class = void>
struct has_yield : std::false_type {};

template<class It>
struct has_yield<It, std::void_t<decltype(std::declval<It&>().yield())>>
  : std::true_type {};


template<class T>
constexpr bool has_yield_v = has_yield<T>::value;
}

template<class T, class V>
class Iterator {
  public:
  using lief_t = V;
  std::unique_ptr<T> next() {
    if (it_ == it_.end()) {
      return nullptr;
    }
    if constexpr (details::has_yield_v<V>) {
      auto owned = it_.yield();
      ++it_;
      return owned ? std::make_unique<T>(std::move(owned)) : nullptr;
    } else {
      return std::make_unique<T>(*it_++);
    }
  }

  uint64_t size() const {
    return it_.size();
  }

  protected:
  Iterator(V it) :
    it_(std::move(it)) {}
  V it_;
};


template<class T, class V>
class ForwardIterator {
  public:
  using lief_t = V;
  std::unique_ptr<T> next() {
    if (begin_ == end_) {
      return nullptr;
    }
    if constexpr (details::has_yield_v<V>) {
      auto owned = begin_.yield();
      ++begin_;
      return owned ? std::make_unique<T>(std::move(owned)) : nullptr;
    } else {
      auto&& value = *begin_;
      ++begin_;
      return std::make_unique<T>(std::move(value));
    }
  }

  auto empty() const {
    return begin_ == end_;
  }

  uint64_t size() const {
    return std::distance(begin_, end_);
  }

  protected:
  ForwardIterator(LIEF::iterator_range<V> range) :
    begin_(std::move(range.begin())),
    end_(std::move(range.end())) {}

  ForwardIterator(V begin, V end) :
    begin_(std::move(begin)),
    end_(std::move(end)) {}

  V begin_;
  V end_;
};

template<class T, class V>
class RandomRangeIterator {
  public:
  using lief_t = V;
  std::unique_ptr<T> next() {
    if (it_ == end_) {
      return nullptr;
    }
    if constexpr (details::has_yield_v<V>) {
      auto owned = it_.yield();
      ++it_;
      return owned ? std::make_unique<T>(std::move(owned)) : nullptr;
    } else {
      return std::make_unique<T>(*it_++);
    }
  }

  uint64_t size() const {
    return std::distance(begin_, end_);
  }

  auto empty() const {
    return begin_ == end_;
  }

  protected:
  RandomRangeIterator(LIEF::iterator_range<V> range) :
    begin_(std::move(range.begin())),
    end_(std::move(range.end())),
    it_(begin_) {}

  RandomRangeIterator(V begin, V end) :
    begin_(std::move(begin)),
    end_(std::move(end)),
    it_(begin_) {}

  V begin_;
  V end_;
  V it_;
};

template<class T, class ContainerT>
class ContainerIterator {
  public:
  ContainerIterator(const ContainerIterator&) = delete;
  ContainerIterator& operator=(const ContainerIterator&) = delete;

  ContainerIterator(ContainerIterator&&) = delete;
  ContainerIterator& operator=(ContainerIterator&&) = delete;

  ~ContainerIterator() = default;

  std::unique_ptr<T> next() {
    if (begin_ == end_) {
      return nullptr;
    }
    return std::make_unique<T>(std::move(*begin_++));
  }

  uint64_t size() const {
    return std::distance(begin_, end_);
  }

  auto empty() const {
    return begin_ == end_;
  }

  protected:
  template<class CT>
  ContainerIterator(CT&& C) :
    container_(std::forward<CT>(C)),
    begin_(std::begin(container_)),
    end_(std::end(container_)) {}

  ContainerT container_;
  typename ContainerT::iterator begin_;
  typename ContainerT::iterator end_;
};
