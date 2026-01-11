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
#include <jni_bind.h>
#include <LIEF/MachO/Binary.hpp>

namespace lief_jni {
template<class T, class V, class J,
  jni::metaprogramming::StringLiteral holder = "impl">
class Iterator {
  public:
  Iterator() = delete;

  Iterator(const Iterator&) = delete;
  Iterator& operator=(const Iterator&) = delete;

  Iterator(Iterator&&) = default;
  Iterator& operator=(Iterator&&) = default;

  auto&& next() {
    return *it_++;
  }

  bool has_next() const {
    return it_ != it_.end();
  }

  uint64_t size() const {
    return it_.size();
  }

  static T* from_jni(jobject thiz) {
    return reinterpret_cast<T*>(
      jni::LocalObject<T::kClass>{thiz}.template Access<holder>().Get()
    );
  }

  static jboolean jni_has_next(JNIEnv* env, jobject thiz) {
    return from_jni(thiz)->has_next();
  }

  static jobject jni_next(JNIEnv* env, jobject thiz) {
    return J::template create<J>(from_jni(thiz)->next());
  }

  static jobject create(V it) {
    return jni::LocalObject<T::kClass>{
      (jlong)new T(std::move(it))
    }.Release();
  }

  protected:
  Iterator(V it) : it_(std::move(it)) {}
  V it_;
};
}
