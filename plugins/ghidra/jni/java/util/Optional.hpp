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
#include <jni_bind.h>
#include "jni/java/util/OptionalInt.hpp"
#include "jni/java/util/OptionalLong.hpp"
#include <LIEF/optional.hpp>

namespace java::util {

template<class T, typename U = T::lief_t>
class Optional {
  public:
  using Element = T;
  static constexpr jni::Class kClass {
    "java/util/Optional",
    jni::Static {
      jni::Method {
        "empty", jni::Return{jni::Self{}}
      },
      jni::Method {
        "of", jni::Return{jni::Self{}}, jni::Params {
          jni::kJavaLangObject
        }
      }
    }
  };

  static jobject empty() {
    return jni::StaticRef<kClass>{}. template Call<"empty">().Release();
  }

  static jobject of(U& impl) {
    jobject jobj = T::create(impl);
    assert (jobj != nullptr);
    return jni::StaticRef<kClass>{}. template Call<"of">(
        jobj
    ).Release();
  }
};

inline jobject make_optional(LIEF::optional<uint32_t> opt) {
  return opt ? OptionalInt::of(*opt) : OptionalInt::empty();
}

inline jobject make_optional(LIEF::result<uint32_t> opt) {
  return opt ? OptionalInt::of(*opt) : OptionalInt::empty();
}

inline jobject make_optional(LIEF::optional<int32_t> opt) {
  return opt ? OptionalInt::of(*opt) : OptionalInt::empty();
}

inline jobject make_optional(LIEF::result<int32_t> opt) {
  return opt ? OptionalInt::of(*opt) : OptionalInt::empty();
}

inline jobject make_optional(LIEF::optional<uint64_t> opt) {
  return opt ? OptionalLong::of(*opt) : OptionalLong::empty();
}

inline jobject make_optional(LIEF::result<uint64_t> opt) {
  return opt ? OptionalLong::of(*opt) : OptionalLong::empty();
}

inline jobject make_optional(LIEF::optional<int64_t> opt) {
  return opt ? OptionalLong::of(*opt) : OptionalLong::empty();
}

inline jobject make_optional(LIEF::result<int64_t> opt) {
  return opt ? OptionalLong::of(*opt) : OptionalLong::empty();
}

template<class T, typename U = T::lief_t>
jobject make_optional(U* impl) {
  if (impl == nullptr) {
    return Optional<T>::empty();
  }
  return Optional<T>::of(*impl);
}
}
