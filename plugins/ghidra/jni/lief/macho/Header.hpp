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

#include <LIEF/MachO/Header.hpp>

namespace lief_jni::macho {

class Header : public JNI<
  Header, LIEF::MachO::Header*>
{
  public:
  using JNI::JNI;
  static constexpr jni::Class kClass {
    "lief/macho/Header",
    jni::Constructor{ jlong{} },
    jni::Field { "impl", jlong{}, }
  };

  class CpuType : public JNIEnum<
    LIEF::MachO::Header::CPU_TYPE, "lief/macho/Header$CpuType">
  {};

  class FileType : public JNIEnum<
    LIEF::MachO::Header::FILE_TYPE, "lief/macho/Header$FileType">
  {};

  static jobject jni_get_cpu_type(JNIEnv* env, jobject thiz) {
    return CpuType::create(
      from_jni(thiz)->impl().cpu_type(), &LIEF::MachO::to_string);
  }

  static jobject jni_get_file_type(JNIEnv* env, jobject thiz) {
    return FileType::create(
      from_jni(thiz)->impl().file_type(), &LIEF::MachO::to_string);
  }

  static jint jni_get_cpu_sub_type(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->impl().cpu_subtype();
  }

  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
