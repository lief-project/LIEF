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

#include "jni/lief/pe/RuntimeFunctionAArch64.hpp"
#include "jni/buffer.hpp"

#include <LIEF/PE/exceptions_info/AArch64/UnpackedFunction.hpp>

namespace lief_jni::pe::aarch64 {

class UnpackedFunction : public RuntimeFunctionAArch64 {
  public:
  using lief_t = LIEF::PE::unwind_aarch64::UnpackedFunction;
  using JNI::create;

  using RuntimeFunctionAArch64::RuntimeFunctionAArch64;

  static constexpr jni::Class kClass {
    "lief/pe/aarch64/UnpackedFunction",
    jni::Constructor{ jlong{} },
  };

  static auto jni_is_extended(JNIEnv* env, jobject thiz) {
    return (jboolean)from_jni(thiz)->cast<lief_t>().is_extended();
  }

  static auto jni_get_xdata_rva(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().xdata_rva();
  }

  static auto jni_get_unwind_code_offset(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->cast<lief_t>().unwind_code_offset();
  }

  static auto jni_get_epilog_scopes_offset(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->cast<lief_t>().epilog_scopes_offset();
  }

  static auto jni_get_nb_epilog_scopes(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->cast<lief_t>().epilog_scopes().size();
  }

  static auto jni_get_exception_handler_offset(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->cast<lief_t>().exception_handler_offset();
  }

  static auto jni_get_unwind_code(JNIEnv* env, jobject thiz) {
    return make_buffer(from_jni(thiz)->cast<lief_t>().unwind_code());
  }

  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
