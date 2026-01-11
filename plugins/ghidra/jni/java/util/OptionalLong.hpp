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

class OptionalLong {
  public:
  static constexpr jni::Class kClass {
    "java/util/OptionalLong",
    jni::Static {
      jni::Method {
        "empty", jni::Return{jni::Self{}}
      },
      jni::Method {
        "of", jni::Return{jni::Self{}}, jni::Params {
          jlong{}
        }
      }
    }
  };

  static jobject empty() {
    return jni::StaticRef<kClass>{}. template Call<"empty">().Release();
  }

  static jobject of(int64_t value) {
    return jni::StaticRef<kClass>{}. template Call<"of">(
        (jlong)value
    ).Release();
  }
};
}
