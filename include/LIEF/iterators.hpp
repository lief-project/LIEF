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
#ifndef LIEF_ITERATORS_H_
#define LIEF_ITERATORS_H_
#include <iostream>
#include <cmath>
#include <iterator>
#include <functional>
#include <algorithm>
#include <type_traits>

#include "LIEF/exception.hpp"

namespace LIEF {

template<class T>
using decay_t = typename std::decay<T>::type;


// Iterator which return ref on container's values
// ===============================================

template<class T>
class ref_iterator : public std::iterator<
                     std::forward_iterator_tag,
                     typename decay_t<T>::value_type,
                     size_t,
                     typename std::remove_pointer<typename decay_t<T>::value_type>::type*,
                     typename std::remove_pointer<typename decay_t<T>::value_type>::type&> {
  public:
  using DT = decay_t<T>;

  ref_iterator(T container) :
    container_{std::forward<T>(container)},
    distance_{0}
  {
    this->it_ = std::begin(container_);
  }

  ref_iterator(const ref_iterator& copy) :
    container_{copy.container_},
    it_{std::begin(container_)},
    distance_{copy.distance_}
  {
    std::advance(this->it_, this->distance_);
  }


  ref_iterator operator=(ref_iterator other) {
    this->swap(other);
    return *this;
  }

  void swap(ref_iterator& other) {
    std::swap(this->container_, other.container_);
    std::swap(this->it_, other.it_);
    std::swap(this->distance_, other.distance_);
  }


  ref_iterator& operator++(void) {
    this->it_ = std::next(this->it_);
    this->distance_++;
    return *this;
  }

  ref_iterator operator++(int) {
    ref_iterator retval = *this;
    ++(*this);
    return retval;
  }

  ref_iterator& operator--(void) {
    if (this->it_ != std::begin(container_)) {
      this->it_ = std::prev(this->it_);
      this->distance_--;
    }
    return *this;
  }

  ref_iterator operator--(int) {
    ref_iterator retval = *this;
    --(*this);
    return retval;
  }


  ref_iterator& operator+=(const typename ref_iterator::difference_type& movement) {
    std::advance(this->it_, movement);
    this->distance_ += movement;
    return *this;
  }


  ref_iterator& operator-=(const typename ref_iterator::difference_type& movement) {
    return (*this) += -movement;
  }


  template<typename U = typename DT::value_type>
  typename std::enable_if<std::is_pointer<U>::value, typename ref_iterator::reference>::type
  operator[](typename ref_iterator::difference_type n) {
    if (n < 0 or n >= this->size()) {
      throw integrity_error(std::to_string(n) + " is out of bound");
    }
    auto it = std::begin(this->container_);
    std::advance(it, n);

    if (*it == nullptr) {
      throw integrity_error("nullptr");
    }
    return **it;

  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<not std::is_pointer<U>::value, typename ref_iterator::reference>::type
  operator[](typename ref_iterator::difference_type n) {
    if (n < 0 or n >= this->size()) {
      throw integrity_error(std::to_string(n) + " is out of bound");
    }
    auto it = std::begin(this->container_);
    std::advance(it, n);
    return *it;
  }

  ref_iterator operator+(typename ref_iterator::difference_type n) const {
    ref_iterator tmp = *this;
    return tmp += n;
  }


  ref_iterator operator-(typename ref_iterator::difference_type n) const {
    ref_iterator tmp = *this;
    return tmp -= n;
  }


  typename ref_iterator::difference_type operator-(const ref_iterator& rhs) const {
    return this->distance_ - rhs.distance_;
  }

  bool operator<(const ref_iterator& rhs) const {
    return (rhs - *this) > 0;
  }


  bool operator>(const ref_iterator& rhs) const {
    return rhs < *this;
  }


  bool operator>=(const ref_iterator& rhs) const {
    return not (*this < rhs);
  }


  bool operator<=(const ref_iterator& rhs) const {
    return not (*this > rhs);
  }

  ref_iterator begin(void) {
    return this->container_;
  }

  ref_iterator end(void)  {
    ref_iterator it = ref_iterator{this->container_};
    it.it_ = std::end(it.container_);
    it.distance_ = it.size();
    return it;
  }

  bool operator==(const ref_iterator& other) const {
    return (this->size() == other.size() and this->distance_ == other.distance_);
  }

  bool operator!=(const ref_iterator& other) const {
    return not (*this == other);
  }

  size_t size(void) const {
    return this->container_.size();
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<std::is_pointer<U>::value, typename ref_iterator::reference>::type
  operator*() {
    if (*this->it_ == nullptr) {
      throw integrity_error("nullptr");
    }
    return **it_;
  }


  template<typename U = typename DT::value_type>
  typename std::enable_if<std::is_pointer<U>::value, typename ref_iterator::pointer>::type
  operator->() {
    if (*this->it_ == nullptr) {
      throw integrity_error("nullptr");
    }
    return *this->it_;
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<not std::is_pointer<U>::value, typename ref_iterator::reference>::type
  operator*() {
    return *(this->it_);
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<not std::is_pointer<U>::value, typename ref_iterator::pointer>::type
  operator->() {
    return &(*this->it_);
  }

  private:
  T container_;
  typename DT::iterator it_;
  typename ref_iterator::difference_type distance_;
};


// Iterator which return const ref on container's values
// =====================================================

template<class T, class CT = typename std::add_const<T>::type>
class const_ref_iterator : public std::iterator<
                     std::forward_iterator_tag,
                     const typename decay_t<T>::value_type,
                     size_t,
                     const typename std::remove_pointer<typename decay_t<T>::value_type>::type*,
                     const typename std::remove_pointer<typename decay_t<T>::value_type>::type&> {
  public:
  using DT = decay_t<CT>;

  const_ref_iterator(CT container) :
    container_{std::forward<CT>(container)},
    distance_{0}
  {
    this->it_ = this->container_.cbegin();
  }


  const_ref_iterator(const const_ref_iterator& copy) :
    container_{copy.container_},
    it_{container_.cbegin()},
    distance_{copy.distance_}
  {
    std::advance(this->it_, this->distance_);
  }

  const_ref_iterator operator=(const_ref_iterator other) {
    this->swap(other);
    return *this;
  }

  void swap(const_ref_iterator& other) {
    std::swap(this->container_, other.container_);
    std::swap(this->it_, other.it_);
    std::swap(this->distance_, other.distance_);
  }



  const_ref_iterator& operator++() {
    this->it_ = std::next(this->it_);
    this->distance_++;
    return *this;
  }

  const_ref_iterator operator++(int) {
    const_ref_iterator retval = *this;
    ++(*this);
    return retval;
  }

  const_ref_iterator& operator--(void) {
    if (this->it_ != container_.cbegin()) {
      this->it_ = std::prev(this->it_);
      this->distance_--;
    }
    return *this;
  }

  const_ref_iterator operator--(int) {
    const_ref_iterator retval = *this;
    --(*this);
    return retval;
  }


  const_ref_iterator& operator+=(const typename const_ref_iterator::difference_type& movement) {
    std::advance(this->it_, movement);
    this->distance_ += movement;
    return *this;
  }


  const_ref_iterator& operator-=(const typename const_ref_iterator::difference_type& movement) {
    return (*this) += -movement;
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<std::is_pointer<U>::value, typename const_ref_iterator::reference>::type
  operator[](typename const_ref_iterator::difference_type n) {
    if (n < 0 or n >= this->size()) {
      throw integrity_error(std::to_string(n) + " is out of bound");
    }
    auto&& it = this->container_.cbegin();
    std::advance(it, n);

    if (*it == nullptr) {
      throw integrity_error("nullptr");
    }
    return **it;

  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<not std::is_pointer<U>::value, typename const_ref_iterator::reference>::type
  operator[](typename const_ref_iterator::difference_type n) {
    auto&& it = this->container_.cbegin();
    std::advance(it, n);
    return *it;
  }

  const_ref_iterator operator+(typename const_ref_iterator::difference_type n) const {
    const_ref_iterator tmp = *this;
    return tmp += n;
  }


  const_ref_iterator operator-(typename const_ref_iterator::difference_type n) const {
    const_ref_iterator tmp = *this;
    return tmp -= n;
  }


  typename const_ref_iterator::difference_type operator-(const const_ref_iterator& rhs) const {
    return this->distance_ - rhs.distance_;
  }

  bool operator<(const const_ref_iterator& rhs) const {
    return (rhs - *this) > 0;
  }


  bool operator>(const const_ref_iterator& rhs) const {
    return rhs < *this;
  }


  bool operator>=(const const_ref_iterator& rhs) const {
    return not (*this < rhs);
  }

  bool operator<=(const const_ref_iterator& rhs) const {
    return not (*this > rhs);
  }

  const_ref_iterator cbegin(void) const {
    return this->container_;
  }

  const_ref_iterator cend(void) const {
    const_ref_iterator it{this->container_};
    it.it_ = it.container_.cend();
    it.distance_ = it.size();
    return it;
  }

  const_ref_iterator begin(void) const {
    return this->cbegin();
  }

  const_ref_iterator end(void) const {
    return this->cend();
  }

  bool operator==(const const_ref_iterator& other) const {
    return (this->size() == other.size() and this->distance_ == other.distance_);
  }

  bool operator!=(const const_ref_iterator& other) const {
    return not (*this == other);
  }

  size_t size(void) const {
    return this->container_.size();
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<std::is_pointer<U>::value, typename const_ref_iterator::reference>::type
  operator*() const {
    if (*this->it_ == nullptr) {
      throw integrity_error("nullptr");
    }
    return **it_;
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<std::is_pointer<U>::value, typename const_ref_iterator::pointer>::type
  operator->() {
    if (*this->it_ == nullptr) {
      throw integrity_error("nullptr");
    }
    return *this->it_;
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<not std::is_pointer<U>::value, typename const_ref_iterator::reference>::type
  operator*() const {
    return *it_;
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<not std::is_pointer<U>::value, typename const_ref_iterator::pointer>::type
  operator->() {
    return &(*this->it_);
  }
  private:
  T container_;
  typename decay_t<decltype(container_)>::const_iterator it_;
  typename const_ref_iterator::difference_type distance_;
};


// Iterator which return a ref on container's values given a predicated
// ====================================================================

template<class T>
class filter_iterator : public std::iterator<
                     std::forward_iterator_tag,
                     typename decay_t<T>::value_type,
                     size_t,
                     typename std::remove_pointer<typename decay_t<T>::value_type>::type*,
                     typename std::remove_pointer<typename decay_t<T>::value_type>::type&> {

  public:

  using DT = decay_t<T>;
  using filter_t = std::function<bool (const typename DT::value_type&)>;

  filter_iterator(T container, filter_t filter) :
    size_c_{0},
    container_{std::forward<T>(container)},
    filter_{filter},
    distance_{0}
  {

    this->it_ = std::begin(this->container_);

    if (this->it_ != std::end(this->container_)) {
      if (not this->filter_(*this->it_)) {
        this->next();
      }
    }
  }

  filter_iterator(const filter_iterator& copy) :
    size_c_{0},
    container_{copy.container_},
    it_{std::begin(container_)},
    filter_{copy.filter_},
    distance_{copy.distance_}
  {
    std::advance(this->it_, this->distance_);
  }

  filter_iterator operator=(filter_iterator other) {
    this->swap(other);
    return *this;
  }

  void swap(filter_iterator& other) {
    std::swap(this->container_, other.container_);
    std::swap(this->it_,        other.it_);
    std::swap(this->filter_,    other.filter_);
    std::swap(this->size_c_,    other.size_c_);
    std::swap(this->distance_,  other.distance_);
  }


  filter_iterator& def(filter_t func) {
    this->filter_ = func;
    this->size_c_ = 0;
    return *this;
  }

  filter_iterator& operator++() {
    this->next();
    return *this;
  }

  filter_iterator operator++(int) {
    filter_iterator retval = *this;
    ++(*this);
    return retval;
  }

  filter_iterator begin(void) {
    return {this->container_, this->filter_};
  }

  filter_iterator end(void) {
    filter_iterator it_end{this->container_, this->filter_};

    it_end.it_       =  it_end.container_.end();
    it_end.distance_ = it_end.container_.size();

    return it_end;
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<std::is_pointer<U>::value, typename filter_iterator::reference>::type
  operator*() {
    if (*this->it_ == nullptr) {
      throw integrity_error("nullptr");
    }
    return **this->it_;
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<!std::is_pointer<U>::value, typename filter_iterator::reference>::type
  operator*() {
    return *this->it_;
  }


  typename filter_iterator::reference
  operator[](typename filter_iterator::difference_type n) {
    if (n < 0 or n >= this->size()) {
      throw integrity_error(std::to_string(n) + " is out of bound");
    }

    auto it = this->begin();
    std::advance(it, n);
    return *it;
  }

  size_t size(void) const {
    if (this->size_c_ > 0) {
      return this->size_c_;
    }
    filter_iterator it = *this;
    size_t size = 0;
    while (it++ != std::end(it)) ++size;
    this->size_c_ = size;
    return this->size_c_;
  }


  bool operator==(const filter_iterator& other) const {
    return (this->container_.size() == other.container_.size() and this->distance_ == other.distance_);
  }

  bool operator!=(const filter_iterator& other) const {
    return not (*this == other);
  }

  private:
  void next(void) {
    if (this->it_ == std::end(this->container_)) {
      this->distance_ = this->container_.size();
      return;
    }

    do {
      this->it_ = std::next(this->it_);
      this->distance_++;
    } while(this->it_ != std::end(this->container_) and not this->filter_(*this->it_));

  }


  mutable size_t size_c_;
  T container_;
  typename DT::iterator it_;
  filter_t filter_;
  typename filter_iterator::difference_type distance_;
};

// Iterator which return a const ref on container's values given a predicated
// ==========================================================================

template<class T, class CT = typename std::add_const<T>::type>
class const_filter_iterator : public std::iterator<
                     std::forward_iterator_tag,
                     const typename decay_t<T>::value_type,
                     std::size_t,
                     const typename std::remove_pointer<typename decay_t<T>::value_type>::type*,
                     const typename std::remove_pointer<typename decay_t<T>::value_type>::type&> {

  public:

  using DT = decay_t<CT>;
  using filter_t = std::function<bool (const typename DT::value_type)>;

  const_filter_iterator(CT container, filter_t filter) :
    size_c_{0},
    container_{std::forward<CT>(container)},
    filter_{filter},
    distance_{0}
  {
    this->it_ = this->container_.cbegin();

    if (this->it_ != this->container_.cend()) {
      if (not this->filter_(*this->it_)) {
        this->next();
      }
    }
  }

  const_filter_iterator(const const_filter_iterator& copy) :
    size_c_{0},
    container_{copy.container_},
    it_{container_.cbegin()},
    filter_{copy.filter_},
    distance_{copy.distance_}
  {
    std::advance(this->it_, this->distance_);
  }

  const_filter_iterator operator=(const_filter_iterator other) {
    this->swap(other);
    return *this;
  }

  void swap(const_filter_iterator& other) {
    std::swap(this->container_, other.container_);
    std::swap(this->it_,        other.it_);
    std::swap(this->filter_,    other.filter_);
    std::swap(this->size_c_,    other.size_c_);
    std::swap(this->distance_,  other.distance_);
  }



  const_filter_iterator& def(filter_t func) {
    this->filter_ = func;
    this->size_c_ = 0;
    return *this;
  }

  const_filter_iterator& operator++() {
    this->next();
    return *this;
  }

  const_filter_iterator operator++(int) {
    const_filter_iterator retval = *this;
    ++(*this);
    return retval;
  }

  const_filter_iterator cbegin(void) const {
    return {this->container_, this->filter_};
  }

  const_filter_iterator cend(void) const {
    const_filter_iterator it{this->container_, this->filter_};
    it.it_       = it.container_.cend();
    it.distance_ = it.container_.size();
    return it;
  }

  const_filter_iterator begin(void) const {
    return this->cbegin();
  }

  const_filter_iterator end(void) const {
    return this->cend();
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<std::is_pointer<U>::value, typename const_filter_iterator::reference>::type
  operator*() const {
    if (*this->it_ == nullptr) {
      throw integrity_error("nullptr");
    }
    return **this->it_;
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<not std::is_pointer<U>::value, typename const_filter_iterator::reference>::type
  operator*() const {
    return *this->it_;
  }


  size_t size(void) const {
    if (this->size_c_ > 0) {
      return this->size_c_;
    }

    auto it = this->cbegin();
    size_t size = 0;
    while (it++ != it.cend()) ++size;
    this->size_c_ = size;
    return this->size_c_;
  }


  typename const_filter_iterator::reference
  operator[](typename const_filter_iterator::difference_type n) const {
    if (n < 0 or n >= this->size()) {
      throw integrity_error(std::to_string(n) + " is out of bound");
    }

    auto it = this->cbegin();
    std::advance(it, n);

    return *it;
  }

  bool operator==(const const_filter_iterator& other) const {
    return (this->container_.size() == other.container_.size() and this->distance_ == other.distance_);
  }

  bool operator!=(const const_filter_iterator& other) const {
    return not (*this == other);
  }

  private:
  void next(void) {

    if (this->it_ == this->container_.cend()) {
      this->distance_ = this->container_.size();
      return;
    }

    do {
      this->it_ = std::next(this->it_);
      this->distance_++;
    } while(this->it_ != this->container_.cend() and not this->filter_(*this->it_));
  }

  mutable size_t size_c_;
  T container_;
  typename decay_t<decltype(container_)>::const_iterator it_;
  filter_t filter_;
  typename const_filter_iterator::difference_type distance_;
};



}

#endif
