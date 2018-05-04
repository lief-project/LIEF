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
#include <cstddef>
#include <iterator>
#include <functional>
#include <algorithm>
#include <type_traits>

#include "LIEF/exception.hpp"

namespace LIEF {

template<class T>
using decay_t = typename std::decay<T>::type;

template<class T>
using add_const_t = typename std::add_const<T>::type;

template<class T>
using remove_const_t = typename std::remove_const<T>::type;

template< class T >
using add_lvalue_reference_t = typename std::add_lvalue_reference<T>::type;


// Iterator which return ref on container's values
// ===============================================

template<class T, class ITERATOR_T = typename decay_t<T>::iterator>
class ref_iterator : public std::iterator<
                     std::bidirectional_iterator_tag,
                     typename decay_t<T>::value_type,
                     ptrdiff_t,
                     typename std::remove_pointer<typename decay_t<T>::value_type>::type*,
                     typename std::remove_pointer<typename decay_t<T>::value_type>::type&> {
  public:
  using container_type = T;
  using DT        = decay_t<T>;
  using ref_t     = typename ref_iterator::reference;
  using pointer_t = typename ref_iterator::pointer;

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
    std::swap(const_cast<add_lvalue_reference_t<remove_const_t<DT>>>(this->container_), const_cast<add_lvalue_reference_t<remove_const_t<DT>>>(other.container_));
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


  typename std::enable_if<not std::is_const<ref_t>::value, remove_const_t<ref_t>>::type
  operator[](size_t n) {
    return const_cast<remove_const_t<ref_t>>(static_cast<const ref_iterator*>(this)->operator[](n));
  }


  add_const_t<ref_t> operator[](size_t n) const {
    if (n >= this->size()) {
      throw integrity_error(std::to_string(n) + " is out of bound");
    }

    ref_iterator* no_const_this = const_cast<ref_iterator*>(this);

	  typename ref_iterator::difference_type saved_dist = std::distance(std::begin(no_const_this->container_), no_const_this->it_);
    no_const_this->it_ = std::begin(no_const_this->container_);
	  std::advance(no_const_this->it_, n);

    auto&& v = const_cast<add_const_t<ref_t>>(no_const_this->operator*());

	  no_const_this->it_ = std::begin(no_const_this->container_);
	  std::advance(no_const_this->it_, saved_dist);

    return v;
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

  ref_iterator begin(void) const {
    return this->container_;
  }

  ref_iterator cbegin(void) const {
    return this->begin();
  }

  ref_iterator end(void)  const {
    ref_iterator it = ref_iterator{this->container_};
    it.it_ = std::end(it.container_);
    it.distance_ = it.size();
    return it;
  }

  ref_iterator cend(void) const {
    return this->end();
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


  typename std::enable_if<not std::is_const<ref_t>::value, remove_const_t<ref_t>>::type
  operator*() {
    return const_cast<remove_const_t<ref_t>>(static_cast<const ref_iterator*>(this)->operator*());
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<std::is_pointer<U>::value, add_const_t<ref_t>>::type
  operator*() const {
    if (*this->it_ == nullptr) {
      throw integrity_error("nullptr");
    }
    return const_cast<add_const_t<ref_t>>(**it_);
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<not std::is_pointer<U>::value, add_const_t<ref_t>>::type
  operator*() const {
    return const_cast<add_const_t<ref_t>>(*(this->it_));
  }


  typename std::enable_if<not std::is_const<pointer_t>::value, pointer_t>::type
  operator->() {
    return const_cast<remove_const_t<pointer_t>>(static_cast<const ref_iterator*>(this)->operator->());
  }

  add_const_t<pointer_t> operator->() const {
    return const_cast<add_const_t<pointer_t>>(&(this->operator*()));
  }

  protected:
  T container_;
  ITERATOR_T it_;
  typename ref_iterator::difference_type distance_;
};


// Iterator which return const ref on container's values
// =====================================================
template<class T, class CT = typename std::add_const<T>::type>
using const_ref_iterator = ref_iterator<CT, typename decay_t<CT>::const_iterator>;


// Iterator which return a ref on container's values given predicates
// ==================================================================

template<class T, class ITERATOR_T = typename decay_t<T>::iterator>
class filter_iterator : public std::iterator<
                     std::forward_iterator_tag,
                     typename decay_t<T>::value_type,
                     ptrdiff_t,
                     typename std::remove_pointer<typename decay_t<T>::value_type>::type*,
                     typename std::remove_pointer<typename decay_t<T>::value_type>::type&> {

  public:
  using container_type = T;
  using DT        = decay_t<T>;
  using ref_t     = typename filter_iterator::reference;
  using pointer_t = typename filter_iterator::pointer;
  using filter_t  = std::function<bool (const typename DT::value_type&)>;

  filter_iterator(T container, filter_t filter) :
    size_c_{0},
    container_{std::forward<T>(container)},
    filters_{},
    distance_{0}
  {

    this->it_ = std::begin(this->container_);

    this->filters_.push_back(filter),
    this->it_ = std::begin(this->container_);

    if (this->it_ != std::end(this->container_)) {
      if (not std::all_of(std::begin(this->filters_), std::end(this->filters_), [this] (const filter_t& f) {return f(*this->it_);})) {
        this->next();
      }
    }
  }

  filter_iterator(T container, const std::vector<filter_t>& filters) :
    size_c_{0},
    container_{std::forward<T>(container)},
    filters_{filters},
    distance_{0}
  {

    this->it_ = std::begin(this->container_);

    if (this->it_ != std::end(this->container_)) {
      if (not std::all_of(std::begin(this->filters_), std::end(this->filters_), [this] (const filter_t& f) {return f(*this->it_);})) {
        this->next();
      }
    }
  }

  filter_iterator(T container) :
    size_c_{0},
    container_{std::forward<T>(container)},
    filters_{},
    distance_{0}
  {
    this->it_ = std::begin(this->container_);
  }

  filter_iterator(const filter_iterator& copy) :
    size_c_{0},
    container_{copy.container_},
    it_{std::begin(container_)},
    filters_{copy.filters_},
    distance_{copy.distance_}
  {
    std::advance(this->it_, this->distance_);
  }

  filter_iterator operator=(filter_iterator other) {
    this->swap(other);
    return *this;
  }

  void swap(filter_iterator& other) {
    std::swap(const_cast<remove_const_t<DT>&>(this->container_), const_cast<remove_const_t<DT>&>(other.container_));
    std::swap(this->it_,        other.it_);
    std::swap(this->filters_,   other.filters_);
    std::swap(this->size_c_,    other.size_c_);
    std::swap(this->distance_,  other.distance_);
  }


  filter_iterator& def(filter_t func) {
    this->filters_.push_back(func);
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

  filter_iterator begin(void) const {
    return {this->container_, this->filters_};
  }

  filter_iterator cbegin(void) const {
    return this->begin();
  }

  filter_iterator end(void) const {
    filter_iterator it_end{this->container_, this->filters_};

    it_end.it_       =  it_end.container_.end();
    it_end.distance_ = it_end.container_.size();

    return it_end;
  }

  filter_iterator cend(void) const {
    return this->end();
  }

  typename std::enable_if<not std::is_const<ref_t>::value, remove_const_t<ref_t>>::type
  operator*() {
    return const_cast<remove_const_t<ref_t>>(static_cast<const filter_iterator*>(this)->operator*());
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<std::is_pointer<U>::value, add_const_t<ref_t>>::type
  operator*() const {
    if (*this->it_ == nullptr) {
      throw integrity_error("nullptr");
    }
    return const_cast<add_const_t<ref_t>>(**it_);
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<not std::is_pointer<U>::value, add_const_t<ref_t>>::type
  operator*() const {
    return const_cast<add_const_t<ref_t>>(*(this->it_));
  }


  typename std::enable_if<not std::is_const<ref_t>::value, remove_const_t<ref_t>>::type
  operator[](size_t n) {
    return const_cast<remove_const_t<ref_t>>(static_cast<const filter_iterator*>(this)->operator[](n));
  }

  add_const_t<ref_t> operator[](size_t n) const {
    if (n >= this->size()) {
      throw integrity_error(std::to_string(n) + " is out of bound");
    }

    auto it = this->begin();
    std::advance(it, n);
    return const_cast<add_const_t<ref_t>>(*it);
  }


  typename std::enable_if<not std::is_const<pointer_t>::value, pointer_t>::type
  operator->() {
    return const_cast<remove_const_t<pointer_t>>(static_cast<const filter_iterator*>(this)->operator->());
  }

  add_const_t<pointer_t> operator->() const {
    return const_cast<add_const_t<pointer_t>>(&(this->operator*()));
  }

  size_t size(void) const {
    if (this->filters_.size() == 0) {
      return this->container_.size();
    }

    if (this->size_c_ > 0) {
      return this->size_c_;
    }
    filter_iterator it = this->begin();
    size_t size = 0;

    while (it++ != std::end(it)) size++;
    this->size_c_ = size;
    return this->size_c_;
  }


  bool operator==(const filter_iterator& other) const {
    return (this->container_.size() == other.container_.size() and this->distance_ == other.distance_);
  }

  bool operator!=(const filter_iterator& other) const {
    return not (*this == other);
  }

  protected:
  void next(void) {
    if (this->it_ == std::end(this->container_)) {
      this->distance_ = this->container_.size();
      return;
    }

    do {
      this->it_ = std::next(this->it_);
      this->distance_++;
    } while(
        this->it_ != std::end(this->container_) and
        not std::all_of(
          std::begin(this->filters_),
          std::end(this->filters_),
          [this] (const filter_t& f) {
            return f(*this->it_);
          }
        )
      );

  }


  mutable size_t size_c_;
  T container_;
  ITERATOR_T it_;
  std::vector<filter_t> filters_;
  typename filter_iterator::difference_type distance_;
};

// Iterator which return a const ref on container's values given predicates
// ========================================================================
template<class T, class CT = typename std::add_const<T>::type>
using const_filter_iterator = filter_iterator<CT, typename decay_t<CT>::const_iterator>;



}

#endif
