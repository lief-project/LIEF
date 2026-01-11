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

#include <LIEF/DWARF/editor/StructType.hpp>

namespace lief_jni::dwarf::editor {

class StructType : public Type {
  public:
  using Type::Type;
  using lief_t = LIEF::dwarf::editor::StructType;
  static constexpr jni::Class kClass {
    "lief/dwarf/editor/StructType",
    jni::Constructor{ jlong{} },
  };

  class Type {
    public:
    static constexpr jni::Class kClass {
      "lief/dwarf/editor/StructType$Type",
    };
  };

  class Member : public JNI<
    Member, std::unique_ptr<LIEF::dwarf::editor::StructType::Member>>
  {
    public:
    static constexpr jni::Class kClass {
      "lief/dwarf/editor/StructType$Member",
      jni::Constructor{ jlong{} },
      jni::Field { "impl", jlong{}, }
    };

    static void jni_destroy(JNIEnv* env, jobject thiz) {
      destroy(thiz);
    }

    static int register_natives(JNIEnv* env);
  };


  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }

  static jobject jni_set_size(JNIEnv* env, jobject thiz, jint size) {
    from_jni(thiz)->cast<lief_t>().set_size((uint64_t)size);
    return thiz;
  }


  static jobject jni_add_member(JNIEnv* env, jobject thiz, jstring name,
                                jobject type, jlong offset)
  {
    jni::LocalString jname = name;
    return Member::create(
      from_jni(thiz)->cast<lief_t>().add_member(
        std::string(jname.Pin().ToString()),
        editor::Type::from_jni(type)->impl(),
        (int64_t)offset
      )
    );
  }
};
}
