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
#include "jni/mirror.hpp"
#include "jni/canbe_unique.hpp"

#include <LIEF/Abstract/Relocation.hpp>

namespace lief_jni::generic {

class Relocation : public JNI<
  Relocation, canbe_unique<LIEF::Relocation>>
{
  public:
  using JNI::JNI;
  static constexpr jni::Class kClass {
    "lief/generic/Relocation",
    jni::Constructor{ jlong{} },
    jni::Field { "impl", jlong{}, }
  };

  static int register_natives(JNIEnv* env);

  static auto jni_get_address(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->impl().address();
  }

  static auto jni_get_size(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->impl().size();
  }

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
