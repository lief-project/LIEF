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
#include "jni/lief/dwarf/editor/Type.hpp"

#include <LIEF/DWARF/editor/EnumType.hpp>

namespace lief_jni::dwarf::editor {

class EnumType : public Type {
  public:
  using Type::Type;
  using lief_t = LIEF::dwarf::editor::EnumType;
  static constexpr jni::Class kClass {
    "lief/dwarf/editor/EnumType",
    jni::Constructor{ jlong{} },
  };

  class Value : public JNI<
    Value, std::unique_ptr<LIEF::dwarf::editor::EnumType::Value>>
  {
    public:
    static constexpr jni::Class kClass {
      "lief/dwarf/editor/EnumType$Value",
      jni::Constructor{ jlong{} },
      jni::Field { "impl", jlong{}, }
    };

    static void jni_destroy(JNIEnv* env, jobject thiz) {
      destroy(thiz);
    }

    static int register_natives(JNIEnv* env);
  };

  static jobject jni_set_size(JNIEnv* env, jobject thiz, jlong size) {
    from_jni(thiz)->cast<lief_t>().set_size((uint64_t)size);
    return thiz;
  }

  static jobject jni_add_value(JNIEnv* env, jobject thiz,
                               jstring name, jlong value)
  {
    jni::LocalString jname = name;
    return Value::create(
      from_jni(thiz)->cast<lief_t>().add_value(
        std::string(jname.Pin().ToString()),
        (int64_t)value
      )
    );
  }

  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
