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

namespace java::lang {

template<class T>
class Enum {
  public:
  using Element = T;
  static constexpr jni::Class kClass {
    "java/lang/Enum",
    jni::Method{"ordinal", jni::Return{jint{}}},
    jni::Method{"name", jni::Return{jstring{}}},
  };

  Enum() = delete;
  Enum(jobject thiz) :
    thiz_(thiz)
  {}

  int ordinal() const {
    return thiz_.template Call<"ordinal">();
  }

  std::string name() const {
    return std::string(jni::LocalString(thiz_.template Call<"name">()).Pin().ToString());
  }

  template<typename U>
  U as() const {
    return static_cast<U>(ordinal());
  }

  protected:
  jni::LocalObject<kClass> thiz_;
};
}
