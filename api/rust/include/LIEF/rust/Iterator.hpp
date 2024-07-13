/* Copyright 2024 R. Thomas
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
#pragma  once
#include <memory>
#include "LIEF/iterators.hpp"

template<class T, class V>
class Iterator {
  public:
  using lief_t = V;
  std::unique_ptr<T> next() {
    if (it_ == it_.end()) return nullptr;
    return std::make_unique<T>(*it_++);
  }

  uint64_t size() const {
    return it_.size();
  }
  protected:
  Iterator(V it) : it_(std::move(it)) {}
  V it_;
};


template<class T, class V>
class ForwardIterator {
  public:
  using lief_t = V;
  std::unique_ptr<T> next() {
    if (begin_ == end_) return nullptr;
    return std::make_unique<T>(*begin_++);
  }
  protected:
  ForwardIterator(LIEF::iterator_range<V> range) :
    begin_(std::move(range.begin())),
    end_(std::move(range.end()))
  {}

  ForwardIterator(V begin, V end) :
    begin_(std::move(begin)),
    end_(std::move(end))
  {}

  V begin_;
  V end_;
};

template<class T, class ContainerT>
class ContainerIterator {
  public:
  std::unique_ptr<T> next() {
    if (begin_ == end_) return nullptr;
    return std::make_unique<T>(*begin_++);
  }
  protected:
  ContainerIterator(ContainerT&& C) :
    container_(std::forward<ContainerT>(C)),
    begin_(std::begin(container_)),
    end_(std::end(container_))
  {}

  ContainerT container_;
  typename ContainerT::iterator begin_;
  typename ContainerT::iterator end_;

};

