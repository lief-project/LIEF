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
#ifndef LIEF_ASSOCIATIVE_ITERATORS_H_
#define LIEF_ASSOCIATIVE_ITERATORS_H_
#include <iostream>
#include <cmath>
#include <cassert>
#include <iterator>
#include <functional>
#include <algorithm>
#include <type_traits>

#include "LIEF/iterators.hpp"
#include "LIEF/exception.hpp"

namespace LIEF {

template<class T>
using decay_t = typename std::decay<T>::type;

template<class T>
using add_const_t = typename std::add_const<T>::type;

template<class T>
using remove_const_t = typename std::remove_const<T>::type;

template<class T>
using add_pointer_t = typename std::add_pointer<T>::type;

template<class T>
using remove_pointer_t = typename std::remove_pointer<T>::type;

template<class T>
using add_ref_t = typename add_lvalue_reference<T>::type;


template<class KEY, class VALUE>
struct dict_iterator_pair {
  public:
  using value_ref_t = remove_pointer_t<decay_t<VALUE>>;
  using key_ref_t = remove_pointer_t<decay_t<KEY>>;

  static_assert(std::is_pointer<VALUE>, "Require pointer!");
  static_assert(std::is_pointer<KEY>, "Require pointer!");

  dict_iterator_pair(KEY key, VALUE value) :
    key_{key},
    value_{value}
  {}

  add_const_t<key_ref_t> key() const {
    return const_cast<add_const_t<key_ref_t>>(key_);
  }

  typename std::enable_if<!std::is_const<key_ref_t>::value, remove_const_t<key_ref_t>>::type
  key() const {
    return const_cast<remove_const_t<key_ref_t>>(static_cast<const dict_iterator_pair*>(this)->key());
  }

  add_const_t<value_ref_t> value() const {
    return const_cast<add_const_t<value_ref_t>>(*value_);
  }

  typename std::enable_if<!std::is_const<value_ref_t>::value, remove_const_t<value_ref_t>>::type
  value() const {
    return const_cast<remove_const_t<value_ref_t>>(static_cast<const dict_iterator_pair*>(this)->value());
  }

  private:
  KEY key_;
  VALUE value_;
};

// Iterator which return ref on container's values
// ===============================================

template<class CONTAINER_T, class ITERATOR_T = typename decay_t<CONTAINER_T>::iterator>
class dict_iterator : public std::iterator<
                     std::bidirectional_iterator_tag,
                     dict_iterator_pair<
                      add_pointer_t<decay_t<remove_pointer_t<typename CONTAINER_T::key_type>>>,
                      add_pointer_t<decay_t<remove_pointer_t<typename CONTAINER_T::mapped_type>>>
                     >,
                     ssize_t,
                     dict_iterator_pair<
                      add_pointer_t<decay_t<remove_pointer_t<typename CONTAINER_T::key_type>>>,
                      add_pointer_t<decay_t<remove_pointer_t<typename CONTAINER_T::mapped_type>>>
                     >*,
                     const dict_iterator_pair<
                      add_pointer_t<decay_t<remove_pointer_t<typename CONTAINER_T::key_type>>>,
                      add_pointer_t<decay_t<remove_pointer_t<typename CONTAINER_T::mapped_type>>>
                     >&> {
  public:
  using DT              = decay_t<T>;
  using value_ref_t     = add_ref_t<remove_pointer_t<decay_t<typename CONTAINER_T::mapped_type>>>;
  using value_pointer_t = add_pointer_t<remove_pointer_t<decay_t<typename CONTAINER_T::mapped_type>>>;

  using key_pointer_t = add_pointer_t<remove_pointer_t<decay_t<typename CONTAINER_T::key_type>>>;

  using keys_iterator_t   = ref_iterator<std::vector<value_pointer_t>>;
  using values_iterator_t = ref_iterator<std::vector<value_pointer_t>>;

  using result_t = dict_iterator_pair<
                      add_pointer_t<decay_t<remove_pointer_t<typename CONTAINER_T::key_type>>>,
                      add_pointer_t<decay_t<remove_pointer_t<typename CONTAINER_T::mapped_type>>>
                     >;

  dict_iterator(T container) :
    container_{std::forward<T>(container)},
    distance_{0}
  {
    it_ = std::begin(container_);
  }

  dict_iterator(const dict_iterator& copy) :
    container_{copy.container_},
    it_{std::begin(container_)},
    distance_{copy.distance_}
  {
    std::advance(it_, distance_);
  }


  dict_iterator operator=(dict_iterator other) {
    swap(other);
    return *this;
  }

  void swap(dict_iterator& other) {
    std::swap(container_, other.container_);
    std::swap(it_, other.it_);
    std::swap(distance_, other.distance_);
  }


  dict_iterator& operator++() {
    it_ = std::next(it_);
    distance_++;
    return *this;
  }

  dict_iterator operator++(int) {
    dict_iterator retval = *this;
    ++(*this);
    return retval;
  }

  dict_iterator& operator--() {
    if (it_ != std::begin(container_)) {
      it_ = std::prev(it_);
      distance_--;
    }
    return *this;
  }

  dict_iterator operator--(int) {
    dict_iterator retval = *this;
    --(*this);
    return retval;
  }


  dict_iterator& operator+=(const typename dict_iterator::difference_type& movement) {
    std::advance(it_, movement);
    distance_ += movement;
    return *this;
  }


  dict_iterator& operator-=(const typename dict_iterator::difference_type& movement) {
    return (*this) += -movement;
  }


  //typename std::enable_if<!std::is_const<ref_t>::value, remove_const_t<ref_t>>::type
  //operator[](size_t n) {
  //  return const_cast<remove_const_t<ref_t>>(static_cast<const dict_iterator*>(this)->operator[](n));
  //}


  //add_const_t<ref_t> operator[](size_t n) const {
  //  assert(n < size() && "integrity_error: out of bound")
  //  auto it = begin();
  //  std::advance(it, n);
  //  return const_cast<add_const_t<ref_t>>(*it);
  //}

  dict_iterator operator+(typename dict_iterator::difference_type n) const {
    dict_iterator tmp = *this;
    return tmp += n;
  }


  dict_iterator operator-(typename dict_iterator::difference_type n) const {
    dict_iterator tmp = *this;
    return tmp -= n;
  }


  typename dict_iterator::difference_type operator-(const dict_iterator& rhs) const {
    return distance_ - rhs.distance_;
  }

  bool operator<(const dict_iterator& rhs) const {
    return (rhs - *this) > 0;
  }


  bool operator>(const dict_iterator& rhs) const {
    return rhs < *this;
  }


  bool operator>=(const dict_iterator& rhs) const {
    return !(*this < rhs);
  }


  bool operator<=(const dict_iterator& rhs) const {
    return !(*this > rhs);
  }

  dict_iterator begin() const {
    return container_;
  }

  dict_iterator cbegin() const {
    return begin();
  }

  dict_iterator end()  const {
    dict_iterator it = dict_iterator{container_};
    it.it_ = std::end(it.container_);
    it.distance_ = it.size();
    return it;
  }

  dict_iterator cend() const {
    return end();
  }

  bool operator==(const dict_iterator& other) const {
    return (size() == other.size() && distance_ == other.distance_);
  }

  bool operator!=(const dict_iterator& other) const {
    return !(*this == other);
  }

  size_t size() const {
    return container_.size();
  }


  typename std::enable_if<!std::is_const<ref_t>::value, remove_const_t<ref_t>>::type
  operator*() {
    return const_cast<remove_const_t<ref_t>>(static_cast<const dict_iterator*>(this)->operator*());
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<std::is_pointer<U>::value, add_const_t<ref_t>>::type
  operator*() const {
    assert(*it_ && "integrity error: nupptr");
    return const_cast<add_const_t<ref_t>>(**it_);
  }

  template<typename U = typename DT::value_type>
  typename std::enable_if<!std::is_pointer<U>::value, add_const_t<ref_t>>::type
  operator*() const {
    return const_cast<add_const_t<ref_t>>(*(it_));
  }


  typename std::enable_if<!std::is_const<pointer_t>::value, pointer_t>::type
  operator->() {
    return const_cast<remove_const_t<pointer_t>>(static_cast<const ref_iterator*>(this)->operator->());
  }

  add_const_t<pointer_t> operator->() const {
    return const_cast<add_const_t<pointer_t>>(&(operator*()));
  }

  protected:
  T container_;
  ITERATOR_T it_;
  typename ref_iterator::difference_type distance_;
};


// Iterator which return const ref on container's values
// =====================================================
//template<class T, class CT = typename std::add_const<T>::type>
//using const_ref_iterator = ref_iterator<CT, typename decay_t<CT>::const_iterator>;



}

#endif
