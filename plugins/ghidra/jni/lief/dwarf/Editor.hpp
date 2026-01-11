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

#include "jni/mirror.hpp"
#include "jni/log.hpp"

#include <jni_bind.h>
#include <LIEF/Abstract/Binary.hpp>
#include <LIEF/DWARF/Editor.hpp>

namespace lief_jni::dwarf {

class Editor : public JNI<Editor, std::unique_ptr<LIEF::dwarf::Editor>> {
  public:
  static constexpr jni::Class kClass {
    "lief/dwarf/Editor",
    jni::Constructor{ jlong{} },
    jni::Field { "impl", jlong{}, }
  };

  class Format {
    public:
    static constexpr jni::Class kClass {
      "lief/dwarf/Editor$Format",
    };
  };

  class Arch {
    public:
    static constexpr jni::Class kClass {
      "lief/dwarf/Editor$Arch",
    };
  };

  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }

  static jobject jni_for_binary(JNIEnv* env, jclass clazz, jobject binary);
  static jobject jni_create(JNIEnv* env, jclass clazz, jobject fmt, jobject arch);
  static jobject jni_create_compilation_unit(JNIEnv* env, jobject thiz);

  static void jni_write(JNIEnv* env, jobject thiz, jstring path) {
    jni::LocalString jpath = path;
    GHIDRA_INFO("DWARF written to {}", jpath.Pin().ToString());
    from_jni(thiz)->impl().write(std::string(jpath.Pin().ToString()));
  }
};
}
