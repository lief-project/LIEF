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

#include <LIEF/PE/CodeIntegrity.hpp>

namespace lief_jni::pe {

class CodeIntegrity : public JNI<
  CodeIntegrity, canbe_unique<LIEF::PE::CodeIntegrity>>
{
  public:
  using lief_t = LIEF::PE::CodeIntegrity;

  static constexpr jni::Class kClass {
    "lief/pe/CodeIntegrity",
    jni::Constructor{ jlong{} },
    jni::Field { "impl", jlong{}, }
  };

  static int register_natives(JNIEnv* env);

  static jshort jni_get_flags(JNIEnv* env, jobject thiz) {
    return (jshort)from_jni(thiz)->cast<lief_t>().flags();
  }

  static jshort jni_get_catalog(JNIEnv* env, jobject thiz) {
    return (jshort)from_jni(thiz)->cast<lief_t>().catalog();
  }

  static jint jni_get_catalog_offset(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().catalog_offset();
  }

  static jint jni_get_reserved(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().reserved();
  }

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
