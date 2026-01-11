/* Copyright 2022 - 2026 R. Thomas
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
#include <cassert>
#include <jni.h>
#include <jni_bind.h>
#include "jni/log.hpp"

#include <spdlog/fmt/compile.h>
#include <spdlog/fmt/fmt.h>

namespace lief_jni {

// from: https://stackoverflow.com/a/55377775
namespace detail {
  // If `*(object of type T)` is valid, this is selected and
  // the return type is `std::true_type`
  template<class T>
  decltype(static_cast<void>(*std::declval<T>()), std::true_type{})
  can_be_dereferenced_impl(int);

  // Otherwise the less specific function is selected,
  // and the return type is `std::false_type`
  template<class>
  std::false_type can_be_dereferenced_impl(...);
}

template<class T>
struct can_be_dereferenced : decltype(detail::can_be_dereferenced_impl<T>(0)) {};

template<class T>
constexpr bool can_be_dereferenced_v = can_be_dereferenced<T>::value;

template<class T,
  typename Wrapper,
  jni::metaprogramming::StringLiteral holder = "impl">
class JNI {
  public:
  using WrapperTy = Wrapper;

  static T* from_jni(jobject thiz) {
    return reinterpret_cast<T*>(
      jni::LocalObject<T::kClass>{thiz}.template Access<holder>().Get()
    );
  }

  static void destroy(jobject thiz) {
    GHIDRA_DEBUG("Destroying: {}", T::kClass.name_);
    jni::LocalObject<T::kClass> obj{thiz};
    delete reinterpret_cast<T*>(
      obj.template Access<holder>().Get()
    );
    obj.template Access<holder>().Set(0);
  }

  auto&& impl() const {
    if constexpr (can_be_dereferenced_v<WrapperTy>) {
      assert(impl_ != nullptr);
      return *impl_;
    } else {
      return impl_;
    }
  }

  auto&& impl() {
    if constexpr (can_be_dereferenced_v<WrapperTy>) {
      assert(impl_ != nullptr);
      return *impl_;
    } else {
      return impl_;
    }
  }

  template<typename U>
  const U& cast() const {
    if constexpr (can_be_dereferenced_v<WrapperTy>) {
      assert(impl_ != nullptr);
      return static_cast<const U&>(*impl_);
    } else {
      return static_cast<const U&>(impl_);
    }
  }

  template<typename U>
  U& cast() {
    if constexpr (can_be_dereferenced_v<WrapperTy>) {
      assert(impl_ != nullptr);
      return static_cast<U&>(*impl_);
    } else {
      return static_cast<U&>(impl_);
    }
  }

  template<class U>
  JNI(U&& impl) :
    impl_(std::forward<U>(impl))
  {}

  JNI() = delete;

  JNI(const JNI&) = delete;
  JNI& operator=(const JNI&) = delete;

  JNI(JNI&&) noexcept = default;
  JNI& operator=(JNI&&) noexcept = delete;

  template<typename U = T, class ...Args>
  static jobject create(Args&&... args) {
    auto* jobj = new U(std::forward<Args>(args)...);
    if constexpr (can_be_dereferenced_v<WrapperTy>) {
      if (jobj->impl_ == nullptr) {
        delete jobj;
        return nullptr;
      }
    }
    return jni::LocalObject<U::kClass>{
      (jlong)jobj
    }.Release();
  }

  protected:
  WrapperTy impl_;
};

template<class T, jni::metaprogramming::StringLiteral JavaName>
class JNIEnum {
  public:
  static_assert(std::is_enum_v<T>);
  using underlying_t = typename std::underlying_type_t<T>;
  using convert_t = const char*(*)(T);
  static constexpr jni::Class kClass {
    JavaName.value,
    jni::Static {
      jni::Method {
        "valueOf", jni::Return{jni::Self{}}, jni::Params{
          jstring{},
        }
      }
    }
  };

  static jobject create(T value, const convert_t& C) {
    return jni::StaticRef<kClass>{}. template Call<"valueOf">(
      (jstring)jni::LocalString(C(value))
    ).Release();
  }
};

}
