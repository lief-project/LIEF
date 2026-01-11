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

#include <LIEF/PE/ExceptionInfo.hpp>

namespace lief_jni::pe {

class ExceptionInfo : public JNI<
  ExceptionInfo, canbe_unique<LIEF::PE::ExceptionInfo>>
{
  public:
  using JNI::JNI;
  using lief_t = LIEF::PE::ExceptionInfo;

  static constexpr jni::Class kClass {
    "lief/pe/ExceptionInfo",
    jni::Constructor{ jlong{} },
    jni::Field { "impl", jlong{}, }
  };

  static jint jni_get_rva(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().rva_start();
  }

  static jint jni_get_offset(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().offset();
  }

  static jobject create_impl(lief_t& impl);

  template<class _>
  static jobject create(lief_t& impl) {
    return create_impl(impl);
  }

  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
