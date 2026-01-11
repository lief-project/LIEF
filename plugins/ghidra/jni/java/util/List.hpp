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

namespace java::util {
template<class T>
class List {
  public:
  using Element = T;
  static constexpr jni::Class kClass {
    "java/util/List",
    jni::Method{"size", jni::Return{jint{}}},
    jni::Method{"get", jni::Return{jni::kJavaLangObject}, jni::Params{jint{}}},
  };

  List() = delete;
  List(jobject thiz) :
    thiz_(thiz)
  {}

  size_t size() const {
    return thiz_.template Call<"size">();
  }

  jni::LocalObject<T::kClass> get(int idx) const {
    return thiz_.template Call<"get">(jint{idx}).Release();
  }

  template<class F>
  void iterate(F&& f) {
    int count = this->size();
    if (count == 0) {
      return;
    }
    for (size_t i = 0; i < count; ++i) {
      f(get(i));
    }
  }

  protected:
  jni::LocalObject<kClass> thiz_;
};
}
