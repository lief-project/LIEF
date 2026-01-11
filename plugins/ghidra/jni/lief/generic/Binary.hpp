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
#include "jni/java/util/Optional.hpp"

#include <LIEF/Abstract/Binary.hpp>

namespace lief_jni::generic {

class Binary : public JNI<
  Binary, canbe_unique<LIEF::Binary>>
{
  public:
  using JNI::JNI;
  static constexpr jni::Class kClass {
    "lief/generic/Binary",
    jni::Constructor{ jlong{} },
    jni::Field { "impl", jlong{}, }
  };

  static jlong jni_get_imagebase(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->impl().imagebase();
  }

  static jobject jni_offset_to_virtual_address(JNIEnv* env, jobject thiz, jlong offset, jlong slide) {
    return java::util::make_optional(from_jni(thiz)->impl().offset_to_virtual_address(offset, slide));
  }

  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
