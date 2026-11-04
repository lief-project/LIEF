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
#include <cstddef>
#include <memory>
#include <utility>

namespace lief_jni {
template<class T>
class canbe_unique {
  public:
  canbe_unique() = default;
  canbe_unique(const canbe_unique&) = delete;
  canbe_unique& operator=(const canbe_unique&) = delete;

  canbe_unique& operator=(std::nullptr_t) {
    reset();
    return *this;
  }

  canbe_unique(canbe_unique&& other) noexcept :
    ptr_(std::exchange(other.ptr_, nullptr)),
    owned_(std::exchange(other.owned_, false)) {}

  canbe_unique& operator=(canbe_unique&& other) noexcept {
    canbe_unique tmp(std::move(other));
    std::swap(ptr_, tmp.ptr_);
    std::swap(owned_, tmp.owned_);
    return *this;
  }

  canbe_unique(T& ptr) :
    ptr_(std::addressof(ptr)) {}

  canbe_unique(const T& ptr) :
    ptr_(const_cast<T*>(std::addressof(ptr))) {}

  canbe_unique(const T&&) = delete;

  canbe_unique(std::unique_ptr<T> unique_ptr) :
    ptr_(unique_ptr.release()),
    owned_(true) {}

  T* get() {
    return ptr_;
  }

  bool is_owned() const {
    return owned_;
  }

  const T* get() const {
    return ptr_;
  }

  T* operator->() {
    return ptr_;
  }

  const T* operator->() const {
    return ptr_;
  }

  T& operator*() {
    return *ptr_;
  }

  const T& operator*() const {
    return *ptr_;
  }

  void reset() {
    T* ptr = std::exchange(ptr_, nullptr);
    if (std::exchange(owned_, false)) {
      std::default_delete<T>()(ptr);
    }
  }

  explicit operator bool() const {
    return ptr_ != nullptr;
  }

  ~canbe_unique() {
    reset();
  }

  private:
  T* ptr_ = nullptr;
  bool owned_ = false;
};

template<class T>
inline bool operator==(const canbe_unique<T>& lhs, std::nullptr_t) {
  return !lhs;
}

template<class T>
inline bool operator==(std::nullptr_t, const canbe_unique<T>& lhs) {
  return !lhs;
}

template<class T>
inline bool operator!=(const canbe_unique<T>& lhs, std::nullptr_t) {
  return static_cast<bool>(lhs);
}

template<class T>
inline bool operator!=(std::nullptr_t, const canbe_unique<T>& lhs) {
  return static_cast<bool>(lhs);
}

}
